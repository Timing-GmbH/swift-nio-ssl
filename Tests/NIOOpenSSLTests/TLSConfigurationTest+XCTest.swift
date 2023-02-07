//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
//
// TLSConfigurationTest+XCTest.swift
//
import XCTest

///
/// NOTE: This file was generated by generate_linux_tests.rb
///
/// Do NOT edit this file directly as it will be regenerated automatically when needed.
///

extension TLSConfigurationTest {

   static var allTests : [(String, (TLSConfigurationTest) -> () throws -> Void)] {
      return [
                ("testNonOverlappingTLSVersions", testNonOverlappingTLSVersions),
                ("testNonOverlappingCipherSuitesPreTLS13", testNonOverlappingCipherSuitesPreTLS13),
                ("testNonOverlappingCipherSuitesPostTLS13", testNonOverlappingCipherSuitesPostTLS13),
                ("testCannotVerifySelfSigned", testCannotVerifySelfSigned),
                ("testServerCannotValidateClientPreTLS13", testServerCannotValidateClientPreTLS13),
                ("testServerCannotValidateClientPostTLS13", testServerCannotValidateClientPostTLS13),
                ("testMutualValidation", testMutualValidation),
                ("testNonexistentFileObject", testNonexistentFileObject),
           ]
   }
}
