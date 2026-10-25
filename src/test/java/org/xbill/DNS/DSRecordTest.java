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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.utils.base16;

class DSRecordTest {
  @Test
  void ctor_0arg() {
    DSRecord dr = new DSRecord();
    assertThat(dr.getName()).isNull();
    assertThat(dr.getType()).isZero();
    assertThat(dr.getDClass()).isZero();
    assertThat(dr.getTTL()).isZero();
    assertThat(dr.getAlgorithm()).isZero();
    assertThat(dr.getDigestID()).isZero();
    assertThat(dr.getDigest()).isNull();
    assertThat(dr.getFootprint()).isZero();
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
      assertThat(dr.getName()).isEqualTo(m_n);
      assertThat(dr.getDClass()).isEqualTo(DClass.IN);
      assertThat(dr.getType()).isEqualTo(Type.DS);
      assertThat(dr.getTTL()).isEqualTo(m_ttl);
      assertThat(dr.getFootprint()).isEqualTo(m_footprint);
      assertThat(dr.getAlgorithm()).isEqualTo(m_algorithm);
      assertThat(dr.getDigestID()).isEqualTo(m_digestid);
      assertThat(dr.getDigest()).containsExactly(m_digest);
    }

    @Test
    void toosmall_footprint() {
      assertThatExceptionOfType(IllegalArgumentException.class)
          .isThrownBy(
              () -> new DSRecord(m_n, DClass.IN, m_ttl, -1, m_algorithm, m_digestid, m_digest));
    }

    @Test
    void toobig_footprint() {
      assertThatExceptionOfType(IllegalArgumentException.class)
          .isThrownBy(
              () ->
                  new DSRecord(m_n, DClass.IN, m_ttl, 0x10000, m_algorithm, m_digestid, m_digest));
    }

    @Test
    void toosmall_algorithm() {
      assertThatExceptionOfType(IllegalArgumentException.class)
          .isThrownBy(
              () -> new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, -1, m_digestid, m_digest));
    }

    @Test
    void toobig_algorithm() {
      assertThatExceptionOfType(IllegalArgumentException.class)
          .isThrownBy(
              () ->
                  new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, 0x10000, m_digestid, m_digest));
    }

    @Test
    void toosmall_digestid() {
      assertThatExceptionOfType(IllegalArgumentException.class)
          .isThrownBy(
              () -> new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, m_algorithm, -1, m_digest));
    }

    @Test
    void toobig_digestid() {
      assertThatExceptionOfType(IllegalArgumentException.class)
          .isThrownBy(
              () ->
                  new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, m_algorithm, 0x10000, m_digest));
    }

    @Test
    void null_digest() {
      DSRecord dr = new DSRecord(m_n, DClass.IN, m_ttl, m_footprint, m_algorithm, m_digestid, null);
      assertThat(dr.getName()).isEqualTo(m_n);
      assertThat(dr.getDClass()).isEqualTo(DClass.IN);
      assertThat(dr.getType()).isEqualTo(Type.DS);
      assertThat(dr.getTTL()).isEqualTo(m_ttl);
      assertThat(dr.getFootprint()).isEqualTo(m_footprint);
      assertThat(dr.getAlgorithm()).isEqualTo(m_algorithm);
      assertThat(dr.getDigestID()).isEqualTo(m_digestid);
      assertThat(dr.getDigest()).isNull();
    }
  }

  @Test
  void rrFromWire() throws IOException {
    byte[] raw = {
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
    assertThat(dr.getFootprint()).isEqualTo(0xABCD);
    assertThat(dr.getAlgorithm()).isEqualTo(0xEF);
    assertThat(dr.getDigestID()).isEqualTo(0x01);
    assertThat(dr.getDigest()).containsExactly((byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89);
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF + " " + 0xFF + " 23456789AB");

    DSRecord dr = new DSRecord();
    dr.rdataFromString(t, null);
    assertThat(dr.getFootprint()).isEqualTo(0xABCD);
    assertThat(dr.getAlgorithm()).isEqualTo(0xEF);
    assertThat(dr.getDigestID()).isEqualTo(0xFF);
    assertThat(dr.getDigest())
        .containsExactly((byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB);
  }

  @Test
  void rdataFromStringMissingDigest() {
    try (Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF + " " + 0x01)) {
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> new DSRecord().rdataFromString(t, null));
    }
  }

  @Test
  void rdataFromStringInvalidDigestData() {
    try (Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF + " " + 0x01 + " $^")) {
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> new DSRecord().rdataFromString(t, null));
    }
  }

  @ParameterizedTest(name = "digest {0}")
  @CsvSource({
    "1,01020304050607080900 01020304050607080900",
    "2,0102030405060708 0102030405060708 0102030405060708 0102030405060708",
    "3,0102030405060708 0102030405060708 0102030405060708 0102030405060708",
    "4,0102030405060708 0102030405060708 0102030405060708 0102030405060708 0102030405060708 0102030405060708",
    "5,6033725b0ccfc05d 1e9d844d49c6cf89 0b13d5eac9439189 947d5db6c8d1c1ec",
    "255,0102",
  })
  void rdataFromString_validDigestLengths(int digestId, String data) throws IOException {
    Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF + " " + digestId + " " + data);
    DSRecord r = new DSRecord();
    r.rdataFromString(t, null);
    assertThat(r.getDigest()).hasSize(base16.fromString(data).length);
  }

  @Test
  void rdataFromString_emptyDigest() {
    String rr = 0xABCD + " " + 0xEF + " 0 \"\"";
    DSRecord r = new DSRecord();
    try (Tokenizer t = new Tokenizer(rr)) {
      assertDoesNotThrow(() -> r.rdataFromString(t, null));
      assertThat(r.getDigest()).isEmpty();
    }

    assertThat(r.rrToString()).isEqualTo(rr);
  }

  @ParameterizedTest(name = "digest {0}")
  @CsvSource({
    "1,01", "2,01", "3,01", "4,01",
  })
  void rdataFromString_invalidDigestLengths(int digestId, String data) {
    try (Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF + " " + digestId + " " + data)) {
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> new DSRecord().rdataFromString(t, null));
      byte[] b64data = base16.fromString(data);
      assertThatExceptionOfType(IllegalArgumentException.class)
          .isThrownBy(
              () ->
                  new DSRecord(
                      Name.root, DClass.IN, 3600, 1, Algorithm.RSASHA1, digestId, b64data));
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> Record.fromString(Name.root, Type.DS, DClass.IN, 3600, t, null));
    }
  }

  @Test
  void rrToString() throws TextParseException {
    String exp = 0xABCD + " " + 0xEF + " " + 0xFF + " 23456789AB";

    DSRecord dr =
        new DSRecord(
            Name.fromString("The.Name."),
            DClass.IN,
            0x123,
            0xABCD,
            0xEF,
            0xFF,
            new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB});
    assertThat(dr.rrToString()).isEqualTo(exp);
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
            0xFF,
            new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB});

    byte[] exp =
        new byte[] {
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0xFF,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB
        };

    DNSOutput out = new DNSOutput();
    dr.rrToWire(out, null, true);

    assertThat(out.toByteArray()).containsExactly(exp);
  }
}
