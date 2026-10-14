//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// The default trust roots on Windows: the peer's chain is decided by Windows' chain engine, as on
// Darwin it is by Security.framework. Per handshake: build the chain with `CertGetCertificateChain`
// (the peer's certificates help build it but are never anchors), require the role's extended key
// usage, check revocation below the root, and apply the SSL policy with the expected host name.
//
// Loading the system store's certificates into BoringSSL instead would trust the user-writable `CA`
// store and lose usage restrictions, the disallowed store and revocation.
//
// Revocation is soft-fail, as on Darwin: a revoked certificate is rejected, an unreachable
// responder is not. Chain building can reach the network, so it runs off the event loop, and its
// revocation fetches share a few seconds in all, so a responder that never answers cannot stall
// the handshake.

#if os(Windows)
import Dispatch
import NIOCore
import WinSDK

extension SSLConnection {
    func performWindowsCertificateValidation(promise: EventLoopPromise<NIOSSLVerificationResult>) {
        do {
            guard case .default = self.parentContext.configuration.trustRoots ?? .default else {
                preconditionFailure("This callback should only be used if we are using the system-default trust.")
            }

            let peerChain: [[UInt8]] = try self.withPeerCertificateChainBuffers { buffers in
                guard let buffers = buffers else {
                    throw NIOSSLError.unableToValidateCertificate
                }
                return buffers.map { Array($0) }
            }
            let expectedHostname = self.validateHostnames ? self.expectedHostname : nil
            // This force-unwrap is safe as we must have decided if we're a client or a server before validation.
            let peerIsServer = self.role! == .client

            // Additional trust roots anchor a chain the system roots do not; they are tried second.
            let additionalRoots: [[UInt8]] = try self.parentContext.configuration.additionalTrustRoots
                .flatMap { trustRoots -> [NIOSSLCertificate] in
                    guard case .certificates(let certs) = trustRoots else {
                        preconditionFailure(
                            "This callback happens on the request path, file-based additional trust roots should be pre-loaded when creating the SSLContext."
                        )
                    }
                    return certs
                }.map { try $0.toDERBytes() }

            WindowsCertificateVerification.queue.async {
                var result = WindowsCertificateVerification.validate(
                    peerChain: peerChain,
                    expectedHostname: expectedHostname,
                    peerIsServer: peerIsServer
                )
                if case .failure(let reason) = result, reason.isUntrustedRoot, !additionalRoots.isEmpty {
                    result = WindowsCertificateVerification.validate(
                        peerChain: peerChain,
                        expectedHostname: expectedHostname,
                        peerIsServer: peerIsServer,
                        exclusiveRoots: additionalRoots
                    )
                }
                switch result {
                case .success:
                    promise.succeed(.certificateVerified)
                case .failure:
                    promise.succeed(.failed)
                }
            }
        } catch {
            promise.fail(error)
        }
    }
}

/// Verifies a TLS peer chain the way Windows itself would.
enum WindowsCertificateVerification {
    /// Why a chain was rejected, with the Win32 status that says which check failed.
    struct RejectionReason: Error, CustomStringConvertible {
        var summary: String
        var win32Status: DWORD?

        var description: String {
            guard let status = self.win32Status else { return self.summary }
            return "\(self.summary) (0x\(String(status, radix: 16, uppercase: true)))"
        }

        /// The chain ends at a root the engine does not trust, or at no root at all.
        var isUntrustedRoot: Bool {
            self.win32Status == 0x800B_0109 || self.win32Status == 0x800B_010A
        }
    }

    // Constants the WinSDK module does not import: pointer-cast or composed macros.

    /// `((LPCSTR) 2)`: `CERT_STORE_PROV_MEMORY`.
    private static var certStoreProvMemory: LPCSTR? { LPCSTR(bitPattern: 2) }
    /// `((LPCSTR) 4)`: `CERT_CHAIN_POLICY_SSL`.
    private static var certChainPolicySSL: LPCSTR? { LPCSTR(bitPattern: 4) }
    /// `CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS`: the four `..._REV_UNKNOWN_FLAG` bits.
    private static let ignoreAllRevocationUnknownFlags: DWORD = 0x0000_0F00
    /// `X509_ASN_ENCODING | PKCS_7_ASN_ENCODING`, the encoding pair every `Cert*` call here takes.
    private static let encodingTypes = DWORD(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

    /// How long all of one chain's revocation fetches may take together. Windows' default is 15 s
    /// for each URL, so a responder behind a firewall that drops packets outlasts most connect
    /// deadlines.
    static let revocationTimeBudgetMilliseconds: DWORD = 5000

    /// `CERT_CHAIN_PARA` with the fields `wincrypt.h` adds under `CERT_CHAIN_PARA_HAS_EXTRA_FIELDS`,
    /// which the WinSDK module leaves out. Laid out as C lays it out (96 bytes on x64).
    struct ExtendedChainParameters {
        var base = CERT_CHAIN_PARA()
        var requestedIssuancePolicy = CERT_USAGE_MATCH()
        var urlRetrievalTimeout: DWORD = 0
        var checkRevocationFreshnessTime: Int32 = 0
        var revocationFreshnessTime: DWORD = 0
        var cacheResync: UnsafeMutablePointer<FILETIME>? = nil
        var strongSignParameters: UnsafeMutableRawPointer? = nil
        var strongSignFlags: DWORD = 0
    }

    /// Where the blocking chain work runs. Concurrent, so one handshake's revocation fetch does not
    /// hold up another's.
    static let queue = DispatchQueue(label: "io.swiftnio.ssl.windowsValidationQueue", attributes: .concurrent)

    /// The blocking chain decision. `.success` only if Windows accepts the DER-encoded `peerChain`
    /// (leaf first) for the role's authentication of `expectedHostname`; every failure, including a
    /// Win32 call that fails to run, rejects. `nil` for `expectedHostname` skips the name check.
    /// Without `exclusiveRoots` the current user's trust settings decide; with them, only they anchor.
    static func validate(
        peerChain: [[UInt8]],
        expectedHostname: String?,
        peerIsServer: Bool = true,
        exclusiveRoots: [[UInt8]]? = nil
    ) -> Result<Void, RejectionReason> {
        var engine: HCERTCHAINENGINE? = nil
        var exclusiveStore: HCERTSTORE? = nil
        defer {
            if let engine = engine { CertFreeCertificateChainEngine(engine) }
            if let exclusiveStore = exclusiveStore { CertCloseStore(exclusiveStore, 0) }
        }
        if let exclusiveRoots = exclusiveRoots {
            switch Self.makeStore(holding: exclusiveRoots) {
            case .success(let store):
                exclusiveStore = store
            case .failure(let reason):
                return .failure(reason)
            }
            var configuration = CERT_CHAIN_ENGINE_CONFIG()
            configuration.cbSize = DWORD(MemoryLayout<CERT_CHAIN_ENGINE_CONFIG>.size)
            configuration.hExclusiveRoot = exclusiveStore
            guard CertCreateCertificateChainEngine(&configuration, &engine) else {
                let error = GetLastError()
                return .failure(RejectionReason(summary: "CertCreateCertificateChainEngine failed", win32Status: error))
            }
        }
        return Self.validate(
            peerChain: peerChain,
            expectedHostname: expectedHostname,
            peerIsServer: peerIsServer,
            chainEngine: engine
        )
    }

    /// The same decision with a chain engine of the caller's; `nil` is the current user's.
    static func validate(
        peerChain: [[UInt8]],
        expectedHostname: String?,
        peerIsServer: Bool = true,
        chainEngine: HCERTCHAINENGINE?
    ) -> Result<Void, RejectionReason> {
        guard let leaf = peerChain.first else {
            return .failure(RejectionReason(summary: "the peer presented no certificate", win32Status: nil))
        }

        // An in-memory store of everything the peer sent, passed as `hAdditionalStore`: usable for
        // chain building, never as anchors.
        let peerStore: HCERTSTORE
        switch Self.makeStore(holding: peerChain) {
        case .success(let store):
            peerStore = store
        case .failure(let reason):
            return .failure(reason)
        }
        defer { CertCloseStore(peerStore, 0) }

        guard
            let leafContext = leaf.withUnsafeBufferPointer({ buffer in
                CertCreateCertificateContext(Self.encodingTypes, buffer.baseAddress, DWORD(buffer.count))
            })
        else {
            let error = GetLastError()
            return .failure(
                RejectionReason(summary: "CertCreateCertificateContext failed for the leaf", win32Status: error)
            )
        }
        defer { CertFreeCertificateContext(leafContext) }

        // `RequestedUsage` makes Windows honour each root's allowed purposes, so a root trusted only
        // for code signing, say, cannot anchor a TLS chain.
        var requestedOID = Array((peerIsServer ? szOID_PKIX_KP_SERVER_AUTH : szOID_PKIX_KP_CLIENT_AUTH).utf8CString)

        return requestedOID.withUnsafeMutableBufferPointer { oidBuffer in
            var usageIdentifiers: [LPSTR?] = [oidBuffer.baseAddress]

            return usageIdentifiers.withUnsafeMutableBufferPointer { usageBuffer in
                var chainParameters = ExtendedChainParameters()
                chainParameters.base.cbSize = DWORD(MemoryLayout<ExtendedChainParameters>.stride)
                chainParameters.base.RequestedUsage.dwType = DWORD(USAGE_MATCH_TYPE_AND)
                chainParameters.base.RequestedUsage.Usage.cUsageIdentifier = 1
                chainParameters.base.RequestedUsage.Usage.rgpszUsageIdentifier = usageBuffer.baseAddress
                chainParameters.urlRetrievalTimeout = Self.revocationTimeBudgetMilliseconds

                var chainContext: PCCERT_CHAIN_CONTEXT?
                // With the accumulative flag the timeout is the budget for all the chain's
                // revocation fetches together.
                let flags =
                    DWORD(CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT)
                    | DWORD(CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT)
                let built = withUnsafeMutablePointer(to: &chainParameters) { extended in
                    extended.withMemoryRebound(to: CERT_CHAIN_PARA.self, capacity: 1) { parameters in
                        CertGetCertificateChain(
                            chainEngine,
                            leafContext,
                            nil,
                            peerStore,
                            parameters,
                            flags,
                            nil,
                            &chainContext
                        )
                    }
                }

                guard built, let chain = chainContext else {
                    let error = GetLastError()
                    return .failure(RejectionReason(summary: "CertGetCertificateChain failed", win32Status: error))
                }
                defer { CertFreeCertificateChain(chain) }

                return Self.applySSLPolicy(to: chain, expectedHostname: expectedHostname, peerIsServer: peerIsServer)
            }
        }
    }

    /// An in-memory certificate store holding the DER-encoded certificates.
    private static func makeStore(holding certificates: [[UInt8]]) -> Result<HCERTSTORE, RejectionReason> {
        guard let store = CertOpenStore(Self.certStoreProvMemory, 0, 0, DWORD(CERT_STORE_CREATE_NEW_FLAG), nil)
        else {
            let error = GetLastError()
            return .failure(RejectionReason(summary: "CertOpenStore(memory) failed", win32Status: error))
        }
        for der in certificates {
            let added = der.withUnsafeBufferPointer { buffer in
                CertAddEncodedCertificateToStore(
                    store,
                    Self.encodingTypes,
                    buffer.baseAddress,
                    DWORD(buffer.count),
                    DWORD(CERT_STORE_ADD_ALWAYS),
                    nil
                )
            }
            guard added else {
                let error = GetLastError()
                CertCloseStore(store, 0)
                return .failure(RejectionReason(summary: "CertAddEncodedCertificateToStore failed", win32Status: error))
            }
        }
        return .success(store)
    }

    private static func applySSLPolicy(
        to chain: PCCERT_CHAIN_CONTEXT,
        expectedHostname: String?,
        peerIsServer: Bool
    ) -> Result<Void, RejectionReason> {
        var sslPolicy = SSL_EXTRA_CERT_CHAIN_POLICY_PARA()
        sslPolicy.cbSize = DWORD(MemoryLayout<SSL_EXTRA_CERT_CHAIN_POLICY_PARA>.size)
        sslPolicy.dwAuthType = DWORD(peerIsServer ? AUTHTYPE_SERVER : AUTHTYPE_CLIENT)
        sslPolicy.fdwChecks = 0

        // The host name has to outlive the call, so the whole policy check happens inside the
        // buffer's scope.
        func check(serverNamePointer: UnsafeMutablePointer<UInt16>?) -> Result<Void, RejectionReason> {
            var policy = sslPolicy
            policy.pwszServerName = serverNamePointer

            return withUnsafeMutablePointer(to: &policy) { policyPointer in
                var policyParameters = CERT_CHAIN_POLICY_PARA()
                policyParameters.cbSize = DWORD(MemoryLayout<CERT_CHAIN_POLICY_PARA>.size)
                // Soft-fail revocation: a revoked certificate still fails; an unreachable responder
                // does not.
                policyParameters.dwFlags = Self.ignoreAllRevocationUnknownFlags
                policyParameters.pvExtraPolicyPara = UnsafeMutableRawPointer(policyPointer)

                var policyStatus = CERT_CHAIN_POLICY_STATUS()
                policyStatus.cbSize = DWORD(MemoryLayout<CERT_CHAIN_POLICY_STATUS>.size)

                guard CertVerifyCertificateChainPolicy(Self.certChainPolicySSL, chain, &policyParameters, &policyStatus)
                else {
                    let error = GetLastError()
                    return .failure(
                        RejectionReason(summary: "CertVerifyCertificateChainPolicy failed to run", win32Status: error)
                    )
                }

                guard policyStatus.dwError == 0 else {
                    return .failure(
                        RejectionReason(summary: "Windows rejected the certificate chain", win32Status: policyStatus.dwError)
                    )
                }
                return .success(())
            }
        }

        guard let expectedHostname = expectedHostname else {
            return check(serverNamePointer: nil)
        }
        var wideName = Array(expectedHostname.utf16) + [0]
        return wideName.withUnsafeMutableBufferPointer { check(serverNamePointer: $0.baseAddress) }
    }
}
#endif
