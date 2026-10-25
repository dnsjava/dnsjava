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

class SingleNameBaseTest {
  private static class TestClass extends SingleNameBase {
    TestClass() {}

    TestClass(Name name, int type, int dclass, long ttl) {
      super(name, type, dclass, ttl);
    }

    TestClass(Name name, int type, int dclass, long ttl, Name singleName, String desc) {
      super(name, type, dclass, ttl, singleName, desc);
    }

    @Override
    public Name getSingleName() {
      return super.getSingleName();
    }
  }

  @Test
  void ctor() throws TextParseException {
    TestClass tc = new TestClass();
    assertThat(tc.getSingleName()).isNull();

    Name n = Name.fromString("my.name.");
    Name sn = Name.fromString("my.single.name.");

    tc = new TestClass(n, Type.A, DClass.IN, 100L);

    assertThat(tc.getName()).isSameAs(n);
    assertThat(tc.getType()).isEqualTo(Type.A);
    assertThat(tc.getDClass()).isEqualTo(DClass.IN);
    assertThat(tc.getTTL()).isEqualTo(100L);

    tc = new TestClass(n, Type.A, DClass.IN, 100L, sn, "The Description");

    assertThat(tc.getName()).isSameAs(n);
    assertThat(tc.getType()).isEqualTo(Type.A);
    assertThat(tc.getDClass()).isEqualTo(DClass.IN);
    assertThat(tc.getTTL()).isEqualTo(100L);
    assertThat(tc.getSingleName()).isSameAs(sn);
  }

  @Test
  void rrFromWire() throws IOException {
    byte[] raw = {2, 'm', 'y', 6, 's', 'i', 'n', 'g', 'l', 'e', 4, 'n', 'a', 'm', 'e', 0};
    DNSInput in = new DNSInput(raw);

    TestClass tc = new TestClass();
    tc.rrFromWire(in);

    Name exp = Name.fromString("my.single.name.");
    assertThat(tc.getSingleName()).isEqualTo(exp);
  }

  @Test
  void rdataFromString() throws IOException {
    Name exp = Name.fromString("my.single.name.");

    Tokenizer t = new Tokenizer("my.single.name.");
    TestClass tc = new TestClass();
    tc.rdataFromString(t, null);
    assertThat(tc.getSingleName()).isEqualTo(exp);

    try (Tokenizer t2 = new Tokenizer("my.relative.name")) {
      TestClass tc2 = new TestClass();
      assertThatExceptionOfType(RelativeNameException.class)
          .isThrownBy(() -> tc2.rdataFromString(t2, null));
    }
  }

  @Test
  void rrToString() throws IOException {
    Name exp = Name.fromString("my.single.name.");

    Tokenizer t = new Tokenizer("my.single.name.");
    TestClass tc = new TestClass();
    tc.rdataFromString(t, null);
    assertThat(tc.getSingleName()).isEqualTo(exp);

    String out = tc.rrToString();
    assertThat(exp).hasToString(out);
  }

  @Test
  void rrToWire() throws IOException {
    Name n = Name.fromString("my.name.");
    Name sn = Name.fromString("My.Single.Name.");

    // non-canonical (case sensitive)
    TestClass tc = new TestClass(n, Type.A, DClass.IN, 100L, sn, "The Description");
    byte[] exp = {2, 'M', 'y', 6, 'S', 'i', 'n', 'g', 'l', 'e', 4, 'N', 'a', 'm', 'e', 0};

    DNSOutput dout = new DNSOutput();
    tc.rrToWire(dout, null, false);

    byte[] out = dout.toByteArray();
    assertThat(out).containsExactly(exp);

    // canonical (lowercase)
    tc = new TestClass(n, Type.A, DClass.IN, 100L, sn, "The Description");
    exp = new byte[] {2, 'm', 'y', 6, 's', 'i', 'n', 'g', 'l', 'e', 4, 'n', 'a', 'm', 'e', 0};

    dout = new DNSOutput();
    tc.rrToWire(dout, null, true);

    out = dout.toByteArray();
    assertThat(out).containsExactly(exp);
  }
}
