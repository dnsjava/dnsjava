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

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base64;

class KEYBaseTest {
  private static class TestClass extends KEYBase {
    TestClass() {}

    TestClass(
        Name name, int type, int dclass, long ttl, int flags, int proto, int alg, byte[] key) {
      super(name, type, dclass, ttl, flags, proto, alg, key);
    }

    @Override
    protected void rdataFromString(Tokenizer st, Name origin) {}
  }

  @Test
  void ctor() throws TextParseException {
    TestClass tc = new TestClass();
    assertThat(tc.getFlags()).isZero();
    assertThat(tc.getProtocol()).isZero();
    assertThat(tc.getAlgorithm()).isZero();
    assertThat(tc.getKey()).isNull();

    Name n = Name.fromString("my.name.");
    byte[] key = {0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

    tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0xFF, 0xF, 0xE, key);

    assertThat(tc.getName()).isSameAs(n);
    assertThat(tc.getType()).isEqualTo(Type.KEY);
    assertThat(tc.getDClass()).isEqualTo(DClass.IN);
    assertThat(tc.getTTL()).isEqualTo(100L);
    assertThat(tc.getFlags()).isEqualTo(0xFF);
    assertThat(tc.getProtocol()).isEqualTo(0xF);
    assertThat(tc.getAlgorithm()).isEqualTo(0xE);
    assertThat(tc.getKey()).containsExactly(key);
  }

  @Test
  void rrFromWire() throws IOException {
    byte[] raw = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x19, 1, 2, 3, 4, 5};
    DNSInput in = new DNSInput(raw);

    TestClass tc = new TestClass();
    tc.rrFromWire(in);

    assertThat(tc.getFlags()).isEqualTo(0xABCD);
    assertThat(tc.getProtocol()).isEqualTo(0xEF);
    assertThat(tc.getAlgorithm()).isEqualTo(0x19);
    assertThat(tc.getKey()).containsExactly(new byte[] {1, 2, 3, 4, 5});

    raw = new byte[] {(byte) 0xBA, (byte) 0xDA, (byte) 0xFF, (byte) 0x28};
    in = new DNSInput(raw);

    tc = new TestClass();
    tc.rrFromWire(in);

    assertThat(tc.getFlags()).isEqualTo(0xBADA);
    assertThat(tc.getProtocol()).isEqualTo(0xFF);
    assertThat(tc.getAlgorithm()).isEqualTo(0x28);
    assertThat(tc.getKey()).isNull();
  }

  @Test
  void rrToString() throws IOException {
    Name n = Name.fromString("my.name.");
    byte[] key = {0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

    TestClass tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0xFF, 0xF, 0xE, null);

    String out = tc.rrToString();

    assertThat(out).isEqualTo("255 15 14");

    tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0xFF, 0xF, 0xE, key);
    out = tc.rrToString();

    assertThat(out).isEqualTo("255 15 14 " + base64.toString(key));

    Options.set("multiline");
    out = tc.rrToString();
    assertThat(out).isEqualTo("255 15 14 (\n\t" + base64.toString(key) + " ) ; key_tag = 18509");

    Options.unset("multiline");
  }

  @Test
  void getFootprint() throws TextParseException {
    Name n = Name.fromString("my.name.");
    byte[] key = {0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

    TestClass tc =
        new TestClass(n, Type.KEY, DClass.IN, 100L, 0xFF, 0xF, DNSSEC.Algorithm.RSAMD5, key);

    int foot = tc.getFootprint();
    // second-to-last and third-to-last bytes of key for RSAMD5
    assertThat(foot).isEqualTo(0xD0E);
    assertThat(tc.getFootprint()).isEqualTo(foot);

    // key with an odd number of bytes
    tc =
        new TestClass(
            n, Type.KEY, DClass.IN, 100L, 0x89AB, 0xCD, 0xEF, new byte[] {0x12, 0x34, 0x56});

    // rrToWire gives: '{ 0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56 }'
    // 89AB + CDEF + 1234 + 5600 = 1BCFE
    // 1BFCE + 1 = 1BFCF & FFFF = BFCF
    foot = tc.getFootprint();
    assertThat(foot).isEqualTo(0xBFCF);
    assertThat(tc.getFootprint()).isEqualTo(foot);

    // empty
    tc = new TestClass();
    assertThat(tc.getFootprint()).isZero();
  }

  @Test
  void rrToWire() throws IOException {
    Name n = Name.fromString("my.name.");
    byte[] key = {0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

    TestClass tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0x7689, 0xAB, 0xCD, key);

    byte[] exp = {
      (byte) 0x76,
      (byte) 0x89,
      (byte) 0xAB,
      (byte) 0xCD,
      0,
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15
    };

    DNSOutput o = new DNSOutput();

    // canonical
    tc.rrToWire(o, null, true);
    assertThat(o.toByteArray()).containsExactly(exp);

    // not canonical
    o = new DNSOutput();
    tc.rrToWire(o, null, false);
    assertThat(o.toByteArray()).containsExactly(exp);
  }
}
