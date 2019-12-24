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

class SetResponseTest {
  @Test
  void ctor_1arg() {
    final int[] types =
        new int[] {
          SetResponse.UNKNOWN,
          SetResponse.NXDOMAIN,
          SetResponse.NXRRSET,
          SetResponse.DELEGATION,
          SetResponse.CNAME,
          SetResponse.DNAME,
          SetResponse.SUCCESSFUL
        };

    for (int type : types) {
      SetResponse sr = new SetResponse(type);
      assertNull(sr.getNS());
      assertEquals(type == SetResponse.UNKNOWN, sr.isUnknown());
      assertEquals(type == SetResponse.NXDOMAIN, sr.isNXDOMAIN());
      assertEquals(type == SetResponse.NXRRSET, sr.isNXRRSET());
      assertEquals(type == SetResponse.DELEGATION, sr.isDelegation());
      assertEquals(type == SetResponse.CNAME, sr.isCNAME());
      assertEquals(type == SetResponse.DNAME, sr.isDNAME());
      assertEquals(type == SetResponse.SUCCESSFUL, sr.isSuccessful());
    }
  }

  @Test
  void ctor_1arg_toosmall() {
    assertThrows(IllegalArgumentException.class, () -> new SetResponse(-1));
  }

  @Test
  void ctor_1arg_toobig() {
    assertThrows(IllegalArgumentException.class, () -> new SetResponse(7));
  }

  @Test
  void ctor_2arg() {
    final int[] types =
        new int[] {
          SetResponse.UNKNOWN,
          SetResponse.NXDOMAIN,
          SetResponse.NXRRSET,
          SetResponse.DELEGATION,
          SetResponse.CNAME,
          SetResponse.DNAME,
          SetResponse.SUCCESSFUL
        };

    for (int type : types) {
      RRset rs = new RRset();
      SetResponse sr = new SetResponse(type, rs);
      assertSame(rs, sr.getNS());
      assertEquals(type == SetResponse.UNKNOWN, sr.isUnknown());
      assertEquals(type == SetResponse.NXDOMAIN, sr.isNXDOMAIN());
      assertEquals(type == SetResponse.NXRRSET, sr.isNXRRSET());
      assertEquals(type == SetResponse.DELEGATION, sr.isDelegation());
      assertEquals(type == SetResponse.CNAME, sr.isCNAME());
      assertEquals(type == SetResponse.DNAME, sr.isDNAME());
      assertEquals(type == SetResponse.SUCCESSFUL, sr.isSuccessful());
    }
  }

  @Test
  void ctor_2arg_toosmall() {
    assertThrows(IllegalArgumentException.class, () -> new SetResponse(-1, new RRset()));
  }

  @Test
  void ctor_2arg_toobig() {
    assertThrows(IllegalArgumentException.class, () -> new SetResponse(7, new RRset()));
  }

  @Test
  void ofType_basic() {
    final int[] types =
        new int[] {
          SetResponse.DELEGATION, SetResponse.CNAME, SetResponse.DNAME, SetResponse.SUCCESSFUL
        };

    for (int type : types) {
      SetResponse sr = SetResponse.ofType(type);
      assertNull(sr.getNS());
      assertEquals(type == SetResponse.UNKNOWN, sr.isUnknown());
      assertEquals(type == SetResponse.NXDOMAIN, sr.isNXDOMAIN());
      assertEquals(type == SetResponse.NXRRSET, sr.isNXRRSET());
      assertEquals(type == SetResponse.DELEGATION, sr.isDelegation());
      assertEquals(type == SetResponse.CNAME, sr.isCNAME());
      assertEquals(type == SetResponse.DNAME, sr.isDNAME());
      assertEquals(type == SetResponse.SUCCESSFUL, sr.isSuccessful());

      SetResponse sr2 = SetResponse.ofType(type);
      assertNotSame(sr, sr2);
    }
  }

  @Test
  void ofType_singleton() {
    final int[] types = new int[] {SetResponse.UNKNOWN, SetResponse.NXDOMAIN, SetResponse.NXRRSET};

    for (int type : types) {
      SetResponse sr = SetResponse.ofType(type);
      assertNull(sr.getNS());
      assertEquals(type == SetResponse.UNKNOWN, sr.isUnknown());
      assertEquals(type == SetResponse.NXDOMAIN, sr.isNXDOMAIN());
      assertEquals(type == SetResponse.NXRRSET, sr.isNXRRSET());
      assertEquals(type == SetResponse.DELEGATION, sr.isDelegation());
      assertEquals(type == SetResponse.CNAME, sr.isCNAME());
      assertEquals(type == SetResponse.DNAME, sr.isDNAME());
      assertEquals(type == SetResponse.SUCCESSFUL, sr.isSuccessful());

      SetResponse sr2 = SetResponse.ofType(type);
      assertSame(sr, sr2);
    }
  }

  @Test
  void ofType_toosmall() {
    assertThrows(IllegalArgumentException.class, () -> SetResponse.ofType(-1));
  }

  @Test
  void ofType_toobig() {
    assertThrows(IllegalArgumentException.class, () -> SetResponse.ofType(7));
  }

  @Test
  void addRRset() throws TextParseException, UnknownHostException {
    RRset rrs = new RRset();
    rrs.addRR(
        new ARecord(
            Name.fromString("The.Name."), DClass.IN, 0xABCD, InetAddress.getByName("192.168.0.1")));
    rrs.addRR(
        new ARecord(
            Name.fromString("The.Name."), DClass.IN, 0xABCD, InetAddress.getByName("192.168.0.2")));
    SetResponse sr = new SetResponse(SetResponse.SUCCESSFUL);
    sr.addRRset(rrs);

    RRset[] exp = new RRset[] {rrs};
    assertArrayEquals(exp, sr.answers().toArray());
  }

  @Test
  void addRRset_multiple() throws TextParseException, UnknownHostException {
    RRset rrs = new RRset();
    rrs.addRR(
        new ARecord(
            Name.fromString("The.Name."), DClass.IN, 0xABCD, InetAddress.getByName("192.168.0.1")));
    rrs.addRR(
        new ARecord(
            Name.fromString("The.Name."), DClass.IN, 0xABCD, InetAddress.getByName("192.168.0.2")));

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

    SetResponse sr = new SetResponse(SetResponse.SUCCESSFUL);
    sr.addRRset(rrs);
    sr.addRRset(rrs2);

    RRset[] exp = new RRset[] {rrs, rrs2};
    assertArrayEquals(exp, sr.answers().toArray());
  }

  @Test
  void answers_nonSUCCESSFUL() {
    SetResponse sr = new SetResponse(SetResponse.UNKNOWN, new RRset());
    assertNull(sr.answers());
  }

  @Test
  void getCNAME() throws TextParseException {
    RRset rrs = new RRset();
    CNAMERecord cr =
        new CNAMERecord(
            Name.fromString("The.Name."), DClass.IN, 0xABCD, Name.fromString("The.Alias."));
    rrs.addRR(cr);
    SetResponse sr = new SetResponse(SetResponse.CNAME, rrs);
    assertEquals(cr, sr.getCNAME());
  }

  @Test
  void getDNAME() throws TextParseException {
    RRset rrs = new RRset();
    DNAMERecord dr =
        new DNAMERecord(
            Name.fromString("The.Name."), DClass.IN, 0xABCD, Name.fromString("The.Alias."));
    rrs.addRR(dr);
    SetResponse sr = new SetResponse(SetResponse.DNAME, rrs);
    assertEquals(dr, sr.getDNAME());
  }

  @Test
  void test_toString() throws TextParseException, UnknownHostException {
    final int[] types =
        new int[] {
          SetResponse.UNKNOWN,
          SetResponse.NXDOMAIN,
          SetResponse.NXRRSET,
          SetResponse.DELEGATION,
          SetResponse.CNAME,
          SetResponse.DNAME,
          SetResponse.SUCCESSFUL
        };
    RRset rrs = new RRset();
    rrs.addRR(
        new ARecord(
            Name.fromString("The.Name."), DClass.IN, 0xABCD, InetAddress.getByName("192.168.0.1")));

    final String[] labels =
        new String[] {
          "unknown",
          "NXDOMAIN",
          "NXRRSET",
          "delegation: " + rrs,
          "CNAME: " + rrs,
          "DNAME: " + rrs,
          "successful"
        };

    for (int i = 0; i < types.length; ++i) {
      SetResponse sr = new SetResponse(types[i], rrs);
      assertEquals(labels[i], sr.toString());
    }
  }
}
