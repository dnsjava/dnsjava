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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DSRecordTest {
  @Test
  void ctor_0arg() {
    DSRecord dr = new DSRecord();
    assertNull(dr.getName());
    assertEquals(0, dr.getType());
    assertEquals(0, dr.getDClass());
    assertEquals(0, dr.getTTL());
    assertEquals(0, dr.getAlgorithm());
    assertEquals(0, dr.getDigestID());
    assertNull(dr.getDigest());
    assertEquals(0, dr.getFootprint());
  }

  static class Test_Ctor_7arg {
    private Name m_n;
    private long m_ttl;
    private int m_footprint;
    private int m_algorithm;
    private int m_digestid;
    private byte[] m_digest;

    @BeforeEach
    void setUp() throws TextParseException {
      m_n = Name.fromString("The.Name.");
      m_ttl = 0xABCDL;
      m_footprint = 0xEF01;
      m_algorithm = 0x23;
      m_digestid = 0x45;
      m_digest = new byte[] {(byte) 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
    }

    @Test
    void basic() {
      DSRecord dr =
          new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, m_algorithm, m_digestid, m_digest);
      assertEquals(m_n, dr.getName());
      assertEquals(DClass.IN, dr.getDClass());
      assertEquals(Type.DS, dr.getType());
      assertEquals(m_ttl, dr.getTTL());
      assertEquals(m_footprint, dr.getFootprint());
      assertEquals(m_algorithm, dr.getAlgorithm());
      assertEquals(m_digestid, dr.getDigestID());
      assertArrayEquals(m_digest, dr.getDigest());
    }

    @Test
    void toosmall_footprint() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new DSRecord(m_n, DClass.IN, m_ttl, -1, m_algorithm, m_digestid, m_digest));
    }

    @Test
    void toobig_footprint() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new DSRecord(m_n, DClass.IN, m_ttl, 0x10000, m_algorithm, m_digestid, m_digest));
    }

    @Test
    void toosmall_algorithm() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, -1, m_digestid, m_digest));
    }

    @Test
    void toobig_algorithm() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, 0x10000, m_digestid, m_digest));
    }

    @Test
    void toosmall_digestid() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, m_algorithm, -1, m_digest));
    }

    @Test
    void toobig_digestid() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, m_algorithm, 0x10000, m_digest));
    }

    @Test
    void null_digest() {
      DSRecord dr = new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, m_algorithm, m_digestid, null);
      assertEquals(m_n, dr.getName());
      assertEquals(DClass.IN, dr.getDClass());
      assertEquals(Type.DS, dr.getType());
      assertEquals(m_ttl, dr.getTTL());
      assertEquals(m_footprint, dr.getFootprint());
      assertEquals(m_algorithm, dr.getAlgorithm());
      assertEquals(m_digestid, dr.getDigestID());
      assertNull(dr.getDigest());
    }
  }

  @Test
  void rrFromWire() throws IOException {
    byte[] raw =
        new byte[] {
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89
        };
    DNSInput in = new DNSInput(raw);

    DSRecord dr = new DSRecord();
    dr.rrFromWire(in);
    assertEquals(0xABCD, dr.getFootprint());
    assertEquals(0xEF, dr.getAlgorithm());
    assertEquals(0x01, dr.getDigestID());
    assertArrayEquals(
        new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89}, dr.getDigest());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF + " " + 0x01 + " 23456789AB");

    DSRecord dr = new DSRecord();
    dr.rdataFromString(t, null);
    assertEquals(0xABCD, dr.getFootprint());
    assertEquals(0xEF, dr.getAlgorithm());
    assertEquals(0x01, dr.getDigestID());
    assertArrayEquals(
        new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB},
        dr.getDigest());
  }

  @Test
  void rdataFromStringMissingDigest() {
    Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF + " " + 0x01);
    assertThrows(TextParseException.class, () -> new DSRecord().rdataFromString(t, null));
  }

  @Test
  void rdataFromStringInvalidDigestData() {
    Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF + " " + 0x01 + " $^");
    assertThrows(TextParseException.class, () -> new DSRecord().rdataFromString(t, null));
  }

  @Test
  void rrToString() throws TextParseException {
    String exp = 0xABCD + " " + 0xEF + " " + 0x01 + " 23456789AB";

    DSRecord dr =
        new DSRecord(
            Name.fromString("The.Name."),
            DClass.IN,
            0x123,
            0xABCD,
            0xEF,
            0x01,
            new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB});
    assertEquals(exp, dr.rrToString());
  }

  @Test
  void rrToWire() throws TextParseException {
    DSRecord dr =
        new DSRecord(
            Name.fromString("The.Name."),
            DClass.IN,
            0x123,
            0xABCD,
            0xEF,
            0x01,
            new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB});

    byte[] exp =
        new byte[] {
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB
        };

    DNSOutput out = new DNSOutput();
    dr.rrToWire(out, null, true);

    assertArrayEquals(exp, out.toByteArray());
  }
}
