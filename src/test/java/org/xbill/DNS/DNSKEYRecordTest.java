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

import java.io.IOException;
import org.junit.jupiter.api.Test;

class DNSKEYRecordTest {
  @Test
  void ctor_0arg() {
    DNSKEYRecord ar = new DNSKEYRecord();
    assertThat(ar.getName()).isNull();
    assertThat(ar.getType()).isZero();
    assertThat(ar.getDClass()).isZero();
    assertThat(ar.getTTL()).isZero();
    assertThat(ar.getAlgorithm()).isZero();
    assertThat(ar.getFlags()).isZero();
    assertThat(ar.getFootprint()).isZero();
    assertThat(ar.getProtocol()).isZero();
    assertThat(ar.getKey()).isNull();
  }

  @Test
  void ctor_7arg() throws TextParseException {
    Name n = Name.fromString("My.Absolute.Name.");
    byte[] key = {0, 1, 3, 5, 7, 9};

    DNSKEYRecord kr = new DNSKEYRecord(n, DClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key);
    assertThat(kr.getName()).isEqualTo(n);
    assertThat(kr.getType()).isEqualTo(Type.DNSKEY);
    assertThat(kr.getDClass()).isEqualTo(DClass.IN);
    assertThat(kr.getTTL()).isEqualTo(0x24AC);
    assertThat(kr.getFlags()).isEqualTo(0x9832);
    assertThat(kr.getProtocol()).isEqualTo(0x12);
    assertThat(kr.getAlgorithm()).isEqualTo(0x67);
    assertThat(kr.getKey()).containsExactly(key);
  }

  @Test
  void ctor_7arg_relativeName() throws TextParseException {
    Name r = Name.fromString("My.Relative.Name");
    byte[] key = {0, 1, 3, 5, 7, 9};

    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> new DNSKEYRecord(r, DClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key));
  }

  @Test
  void rdataFromString() throws IOException {
    // basic
    DNSKEYRecord kr = new DNSKEYRecord();
    Tokenizer st = new Tokenizer(0xABCD + " " + 0x81 + " RSASHA1 AQIDBAUGBwgJ");
    kr.rdataFromString(st, null);
    assertThat(kr.getFlags()).isEqualTo(0xABCD);
    assertThat(kr.getProtocol()).isEqualTo(0x81);
    assertThat(kr.getAlgorithm()).isEqualTo(DNSSEC.Algorithm.RSASHA1);
    assertThat(kr.getKey()).containsExactly(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9});
    assertThat(kr.getFootprint()).isEqualTo(17895);
  }

  @Test
  void rdataFromStringUnknownAlgorithm() {
    // Algorithm name 'ZONE' is invalid
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(
            () ->
                new DNSKEYRecord()
                    .rdataFromString(
                        new Tokenizer(0x1212 + " " + 0xAA + " ZONE AQIDBAUGBwgJ"), null));
  }

  @Test
  void rdataFromStringIntAlg() throws IOException {
    DNSKEYRecord kr = new DNSKEYRecord();
    Tokenizer st = new Tokenizer(0xABCD + " " + 0x81 + " 5 AQIDBAUGBwgJ");
    kr.rdataFromString(st, null);
    assertThat(kr.getFlags()).isEqualTo(0xABCD);
    assertThat(kr.getProtocol()).isEqualTo(0x81);
    assertThat(kr.getAlgorithm()).isEqualTo(DNSSEC.Algorithm.RSASHA1);
    assertThat(kr.getKey()).containsExactly(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9});
    assertThat(kr.getFootprint()).isEqualTo(17895);
  }

  @Test
  void rdataFromStringBadIntAlg() {
    // Algorithm number 257 is outside the allowed range
    DNSKEYRecord kr = new DNSKEYRecord();
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(
            () ->
                kr.rdataFromString(new Tokenizer(0xABCD + " " + 0x81 + " 257 AQIDBAUGBwgJ"), null));
  }
}
