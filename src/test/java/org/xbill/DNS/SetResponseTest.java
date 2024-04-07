// SPDX-License-Identifier: BSD-3-Clause
// -*- Java -*-
//
// Copyright (c) 2005, Matthew J. Rutherford <rutherfo@cs.colorado.edu>
// Copyright (c) 2005, University of Colorado at Boulder
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of the University of Colorado at Boulder nor the
//   names of its contributors may be used to endorse or promote
//   products derived from this software without specific prior written
//   permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class SetResponseTest {
  private static final ARecord A_RECORD_1 =
      new ARecord(
          Name.fromConstantString("The.Name."),
          DClass.IN,
          0xABCD,
          new byte[] {(byte) 192, (byte) 168, 0, 1});
  private static final ARecord A_RECORD_2 =
      new ARecord(
          Name.fromConstantString("The.Name."),
          DClass.IN,
          0xABCD,
          new byte[] {(byte) 192, (byte) 168, 0, 2});

  @ParameterizedTest
  @EnumSource(value = SetResponseType.class)
  void ctor_1arg(SetResponseType type) {
    SetResponse sr = SetResponse.ofType(type);
    assertNull(sr.getNS());
    assertEquals(type == SetResponseType.UNKNOWN, sr.isUnknown());
    assertEquals(type == SetResponseType.NXDOMAIN, sr.isNXDOMAIN());
    assertEquals(type == SetResponseType.NXRRSET, sr.isNXRRSET());
    assertEquals(type == SetResponseType.DELEGATION, sr.isDelegation());
    assertEquals(type == SetResponseType.CNAME, sr.isCNAME());
    assertEquals(type == SetResponseType.DNAME, sr.isDNAME());
    assertEquals(type == SetResponseType.SUCCESSFUL, sr.isSuccessful());
  }

  @ParameterizedTest
  @EnumSource(
      value = SetResponseType.class,
      names = {
        "DELEGATION",
        "CNAME",
        "DNAME",
        "SUCCESSFUL",
      })
  void ofType_basic(SetResponseType type) {
    RRset rs = new RRset();
    SetResponse sr = SetResponse.ofType(type, rs);
    assertSame(rs, sr.getNS());
    assertEquals(type == SetResponseType.DELEGATION, sr.isDelegation());
    assertEquals(type == SetResponseType.CNAME, sr.isCNAME());
    assertEquals(type == SetResponseType.DNAME, sr.isDNAME());
    assertEquals(type == SetResponseType.SUCCESSFUL, sr.isSuccessful());

    SetResponse sr2 = SetResponse.ofType(type, rs);
    assertNotSame(sr, sr2);
  }

  @ParameterizedTest
  @EnumSource(
      value = SetResponseType.class,
      names = {
        "UNKNOWN",
        "NXDOMAIN",
        "NXRRSET",
      })
  void ofType_singleton(SetResponseType type) {
    SetResponse sr = SetResponse.ofType(type);
    assertNull(sr.getNS());
    assertEquals(type == SetResponseType.UNKNOWN, sr.isUnknown());
    assertEquals(type == SetResponseType.NXDOMAIN, sr.isNXDOMAIN());
    assertEquals(type == SetResponseType.NXRRSET, sr.isNXRRSET());
    assertThrows(IllegalStateException.class, () -> sr.addRRset(new RRset()));

    SetResponse sr2 = SetResponse.ofType(type);
    assertSame(sr, sr2);
  }

  @Test
  void addRRset() {
    RRset rrs = new RRset();
    rrs.addRR(A_RECORD_1);
    rrs.addRR(A_RECORD_2);
    SetResponse sr = SetResponse.ofType(SetResponseType.SUCCESSFUL, rrs);

    RRset[] exp = new RRset[] {rrs};
    assertArrayEquals(exp, sr.answers().toArray());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void ofTypeWithCachedRRset(boolean isAuthenticated) {
    SetResponse sr =
        SetResponse.ofType(
            SetResponseType.SUCCESSFUL,
            new Cache.CacheRRset(new RRset(A_RECORD_1), 0, 0, isAuthenticated));
    assertEquals(isAuthenticated, sr.isAuthenticated());
  }

  @ParameterizedTest
  @CsvSource({
    "false,true,true,true,true",
    "false,false,true,false,false",
    "true,true,false,true,false",
    "true,false,false,false,false",
  })
  void addRRsetAuthenticated(
      boolean addInitial,
      boolean first,
      boolean second,
      boolean firstResult,
      boolean secondResult) {
    RRset rrs = new RRset(A_RECORD_1);
    SetResponse sr;
    if (addInitial) {
      sr = SetResponse.ofType(SetResponseType.SUCCESSFUL, rrs, first);
    } else {
      sr = SetResponse.ofType(SetResponseType.SUCCESSFUL);
      sr.addRRset(new Cache.CacheRRset(rrs, 0, 0, first));
    }

    RRset[] exp = new RRset[] {rrs};
    assertArrayEquals(exp, sr.answers().toArray());
    assertEquals(firstResult, sr.isAuthenticated());

    sr.addRRset(new Cache.CacheRRset(new RRset(A_RECORD_1), 0, 0, second));
    assertEquals(secondResult, sr.isAuthenticated());
    assertEquals(2, sr.answers().size());
  }

  @Test
  void addRRset_multiple() throws TextParseException, UnknownHostException {
    RRset rrs = new RRset();
    rrs.addRR(A_RECORD_1);
    rrs.addRR(A_RECORD_2);

    RRset rrs2 = new RRset();
    rrs2.addRR(
        new ARecord(
            Name.fromString("The.Other.Name."),
            DClass.IN,
            0xABCE,
            InetAddress.getByName("192.168.1.1")));
    rrs2.addRR(
        new ARecord(
            Name.fromString("The.Other.Name."),
            DClass.IN,
            0xABCE,
            InetAddress.getByName("192.168.1.2")));

    SetResponse sr = SetResponse.ofType(SetResponseType.SUCCESSFUL);
    sr.addRRset(rrs);
    sr.addRRset(rrs2);

    RRset[] exp = new RRset[] {rrs, rrs2};
    assertArrayEquals(exp, sr.answers().toArray());
  }

  @Test
  void answers_nonSUCCESSFUL() {
    SetResponse sr = SetResponse.ofType(SetResponseType.UNKNOWN, new RRset());
    assertNull(sr.answers());
  }

  @Test
  void getCNAME() throws TextParseException {
    CNAMERecord cr =
        new CNAMERecord(
            Name.fromString("The.Name."), DClass.IN, 0xABCD, Name.fromString("The.Alias."));
    RRset rrs = new RRset(cr);
    SetResponse sr = SetResponse.ofType(SetResponseType.CNAME, rrs);
    assertEquals(cr, sr.getCNAME());
  }

  @Test
  void getDNAME() throws TextParseException {
    DNAMERecord dr =
        new DNAMERecord(
            Name.fromString("The.Name."), DClass.IN, 0xABCD, Name.fromString("The.Alias."));
    RRset rrs = new RRset(dr);
    SetResponse sr = SetResponse.ofType(SetResponseType.DNAME, rrs);
    assertEquals(dr, sr.getDNAME());
  }

  @ParameterizedTest
  @EnumSource(SetResponseType.class)
  void test_toString(SetResponseType type) {
    RRset rrs = new RRset(A_RECORD_1);

    SetResponse sr = SetResponse.ofType(type, rrs);
    if (type.isPrintRecords()) {
      assertEquals(type + ": " + rrs, sr.toString());
    } else {
      assertEquals(type.toString(), sr.toString());
    }
  }
}
