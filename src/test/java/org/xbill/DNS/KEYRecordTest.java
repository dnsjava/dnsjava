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

class KEYRecordTest {
  @Test
  void ctor_0arg() {
    KEYRecord ar = new KEYRecord();
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
    Name r = Name.fromString("My.Relative.Name");
    byte[] key = {0, 1, 3, 5, 7, 9};

    KEYRecord kr = new KEYRecord(n, DClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key);
    assertThat(kr.getName()).isEqualTo(n);
    assertThat(kr.getType()).isEqualTo(Type.KEY);
    assertThat(kr.getDClass()).isEqualTo(DClass.IN);
    assertThat(kr.getTTL()).isEqualTo(0x24AC);
    assertThat(kr.getFlags()).isEqualTo(0x9832);
    assertThat(kr.getProtocol()).isEqualTo(0x12);
    assertThat(kr.getAlgorithm()).isEqualTo(0x67);
    assertThat(kr.getKey()).containsExactly(key);

    // a relative name
    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> new KEYRecord(r, DClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key));
  }

  @Test
  void Protocol_string() {
    // a regular one
    assertThat(KEYRecord.Protocol.string(KEYRecord.Protocol.DNSSEC)).isEqualTo("DNSSEC");
    // an unassigned value within range
    assertThat(KEYRecord.Protocol.string(0xFE)).isEqualTo("254");
    // too low
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> KEYRecord.Protocol.string(-1));
    // too high
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> KEYRecord.Protocol.string(0x100));
  }

  @Test
  void Protocol_value() {
    // a regular one
    assertThat(KEYRecord.Protocol.value("IPSEC")).isEqualTo(KEYRecord.Protocol.IPSEC);
    // an unassigned value within range
    assertThat(KEYRecord.Protocol.value("254")).isEqualTo(254);
    // too low
    assertThat(KEYRecord.Protocol.value("-2")).isEqualTo(-1);
    // too high
    assertThat(KEYRecord.Protocol.value("256")).isEqualTo(-1);
  }

  @Test
  void Flags_value() {
    // numeric

    // lower bound
    assertThat(KEYRecord.Flags.value("-2")).isEqualTo(-1);
    assertThat(KEYRecord.Flags.value("0")).isZero();
    // in the middle
    assertThat(KEYRecord.Flags.value(0xAB35 + "")).isEqualTo(0xAB35);
    // upper bound
    assertThat(KEYRecord.Flags.value(0xFFFF + "")).isEqualTo(0xFFFF);
    assertThat(KEYRecord.Flags.value(0x10000 + "")).isEqualTo(-1);

    // textual

    // single
    assertThat(KEYRecord.Flags.value("EXTEND")).isEqualTo(KEYRecord.Flags.EXTEND);
    // single invalid
    assertThat(KEYRecord.Flags.value("NOT_A_VALID_NAME")).isEqualTo(-1);
    // multiple
    assertThat(KEYRecord.Flags.value("NOAUTH|ZONE|FLAG10"))
        .isEqualTo(KEYRecord.Flags.NOAUTH | KEYRecord.Flags.FLAG10 | KEYRecord.Flags.ZONE);
    // multiple invalid
    assertThat(KEYRecord.Flags.value("NOAUTH|INVALID_NAME|FLAG10")).isEqualTo(-1);
    // pathological
    assertThat(KEYRecord.Flags.value("|")).isZero();
  }

  @Test
  void rdataFromString() throws IOException {
    // basic
    KEYRecord kr = new KEYRecord();
    Tokenizer st = new Tokenizer("NOAUTH|ZONE|FLAG10 EMAIL RSASHA1 AQIDBAUGBwgJ");
    kr.rdataFromString(st, null);
    assertThat(kr.getFlags())
        .isEqualTo(KEYRecord.Flags.NOAUTH | KEYRecord.Flags.FLAG10 | KEYRecord.Flags.ZONE);
    assertThat(kr.getProtocol()).isEqualTo(KEYRecord.Protocol.EMAIL);
    assertThat(kr.getAlgorithm()).isEqualTo(DNSSEC.Algorithm.RSASHA1);
    assertThat(kr.getKey()).containsExactly(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9});

    // basic w/o key
    kr = new KEYRecord();
    st = new Tokenizer("NOAUTH|NOKEY|FLAG10 TLS 3");
    kr.rdataFromString(st, null);
    assertThat(kr.getFlags())
        .isEqualTo(KEYRecord.Flags.NOAUTH | KEYRecord.Flags.FLAG10 | KEYRecord.Flags.NOKEY);
    assertThat(kr.getProtocol()).isEqualTo(KEYRecord.Protocol.TLS);
    assertThat(kr.getAlgorithm()).isEqualTo(3); // Was ECC
    assertThat(kr.getKey()).isNull();

    // invalid flags
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(
            () ->
                new KEYRecord()
                    .rdataFromString(
                        new Tokenizer("NOAUTH|ZONE|JUNK EMAIL RSASHA1 AQIDBAUGBwgJ"), null));

    // invalid protocol
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(
            () ->
                new KEYRecord()
                    .rdataFromString(new Tokenizer("NOAUTH|ZONE RSASHA1 3 AQIDBAUGBwgJ"), null));

    // invalid algorithm
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(
            () ->
                new KEYRecord()
                    .rdataFromString(new Tokenizer("NOAUTH|ZONE EMAIL ZONE AQIDBAUGBwgJ"), null));
  }
}
