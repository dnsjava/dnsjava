// SPDX-License-Identifier: BSD-2-Clause
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
import org.junit.jupiter.api.Test;

class KEYRecordTest {
  @Test
  void ctor_0arg() {
    KEYRecord ar = new KEYRecord();
    assertNull(ar.getName());
    assertEquals(0, ar.getType());
    assertEquals(0, ar.getDClass());
    assertEquals(0, ar.getTTL());
    assertEquals(0, ar.getAlgorithm());
    assertEquals(0, ar.getFlags());
    assertEquals(0, ar.getFootprint());
    assertEquals(0, ar.getProtocol());
    assertNull(ar.getKey());
  }

  @Test
  void ctor_7arg() throws TextParseException {
    Name n = Name.fromString("My.Absolute.Name.");
    Name r = Name.fromString("My.Relative.Name");
    byte[] key = new byte[] {0, 1, 3, 5, 7, 9};

    KEYRecord kr = new KEYRecord(n, DClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key);
    assertEquals(n, kr.getName());
    assertEquals(Type.KEY, kr.getType());
    assertEquals(DClass.IN, kr.getDClass());
    assertEquals(0x24AC, kr.getTTL());
    assertEquals(0x9832, kr.getFlags());
    assertEquals(0x12, kr.getProtocol());
    assertEquals(0x67, kr.getAlgorithm());
    assertArrayEquals(key, kr.getKey());

    // a relative name
    assertThrows(
        RelativeNameException.class,
        () -> new KEYRecord(r, DClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key));
  }

  @Test
  void Protocol_string() {
    // a regular one
    assertEquals("DNSSEC", KEYRecord.Protocol.string(KEYRecord.Protocol.DNSSEC));
    // a unassigned value within range
    assertEquals("254", KEYRecord.Protocol.string(0xFE));
    // too low
    assertThrows(IllegalArgumentException.class, () -> KEYRecord.Protocol.string(-1));
    // too high
    assertThrows(IllegalArgumentException.class, () -> KEYRecord.Protocol.string(0x100));
  }

  @Test
  void Protocol_value() {
    // a regular one
    assertEquals(KEYRecord.Protocol.IPSEC, KEYRecord.Protocol.value("IPSEC"));
    // a unassigned value within range
    assertEquals(254, KEYRecord.Protocol.value("254"));
    // too low
    assertEquals(-1, KEYRecord.Protocol.value("-2"));
    // too high
    assertEquals(-1, KEYRecord.Protocol.value("256"));
  }

  @Test
  void Flags_value() {
    // numeric

    // lower bound
    assertEquals(-1, KEYRecord.Flags.value("-2"));
    assertEquals(0, KEYRecord.Flags.value("0"));
    // in the middle
    assertEquals(0xAB35, KEYRecord.Flags.value(0xAB35 + ""));
    // upper bound
    assertEquals(0xFFFF, KEYRecord.Flags.value(0xFFFF + ""));
    assertEquals(-1, KEYRecord.Flags.value(0x10000 + ""));

    // textual

    // single
    assertEquals(KEYRecord.Flags.EXTEND, KEYRecord.Flags.value("EXTEND"));
    // single invalid
    assertEquals(-1, KEYRecord.Flags.value("NOT_A_VALID_NAME"));
    // multiple
    assertEquals(
        KEYRecord.Flags.NOAUTH | KEYRecord.Flags.FLAG10 | KEYRecord.Flags.ZONE,
        KEYRecord.Flags.value("NOAUTH|ZONE|FLAG10"));
    // multiple invalid
    assertEquals(-1, KEYRecord.Flags.value("NOAUTH|INVALID_NAME|FLAG10"));
    // pathological
    assertEquals(0, KEYRecord.Flags.value("|"));
  }

  @Test
  void rdataFromString() throws IOException {
    // basic
    KEYRecord kr = new KEYRecord();
    Tokenizer st = new Tokenizer("NOAUTH|ZONE|FLAG10 EMAIL RSASHA1 AQIDBAUGBwgJ");
    kr.rdataFromString(st, null);
    assertEquals(
        KEYRecord.Flags.NOAUTH | KEYRecord.Flags.FLAG10 | KEYRecord.Flags.ZONE, kr.getFlags());
    assertEquals(KEYRecord.Protocol.EMAIL, kr.getProtocol());
    assertEquals(DNSSEC.Algorithm.RSASHA1, kr.getAlgorithm());
    assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9}, kr.getKey());

    // basic w/o key
    kr = new KEYRecord();
    st = new Tokenizer("NOAUTH|NOKEY|FLAG10 TLS 3");
    kr.rdataFromString(st, null);
    assertEquals(
        KEYRecord.Flags.NOAUTH | KEYRecord.Flags.FLAG10 | KEYRecord.Flags.NOKEY, kr.getFlags());
    assertEquals(KEYRecord.Protocol.TLS, kr.getProtocol());
    assertEquals(3, kr.getAlgorithm()); // Was ECC
    assertNull(kr.getKey());

    // invalid flags
    assertThrows(
        TextParseException.class,
        () ->
            new KEYRecord()
                .rdataFromString(
                    new Tokenizer("NOAUTH|ZONE|JUNK EMAIL RSASHA1 AQIDBAUGBwgJ"), null));

    // invalid protocol
    assertThrows(
        TextParseException.class,
        () ->
            new KEYRecord()
                .rdataFromString(new Tokenizer("NOAUTH|ZONE RSASHA1 3 AQIDBAUGBwgJ"), null));

    // invalid algorithm
    assertThrows(
        TextParseException.class,
        () ->
            new KEYRecord()
                .rdataFromString(new Tokenizer("NOAUTH|ZONE EMAIL ZONE AQIDBAUGBwgJ"), null));
  }
}
