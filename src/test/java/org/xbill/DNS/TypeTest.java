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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class TypeTest {
  @Test
  void string() {
    // a regular one
    assertEquals("CNAME", Type.string(Type.CNAME));

    // one that doesn't exist
    assertTrue(Type.string(65535).startsWith("TYPE"));

    assertThrows(IllegalArgumentException.class, () -> Type.string(-1));
  }

  @Test
  void value() {
    // regular one
    assertEquals(Type.MAILB, Type.value("MAILB"));

    // one thats undefined but within range
    assertEquals(300, Type.value("TYPE300"));

    // something that unknown
    assertEquals(-1, Type.value("THIS IS DEFINITELY UNKNOWN"));

    // empty string
    assertEquals(-1, Type.value(""));
  }

  @Test
  void value_2arg() {
    assertEquals(301, Type.value("301", true));
  }

  @Test
  void isRR() {
    assertTrue(Type.isRR(Type.CNAME));
    assertFalse(Type.isRR(Type.IXFR));
  }

  static class Priv1Record extends Record {
    Integer value;

    @Override
    void rrFromWire(DNSInput in) {}

    @Override
    String rrToString() {
      return value.toString();
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
      value = st.getUInt16();
    }

    @Override
    void rrToWire(DNSOutput out, Compression c, boolean canonical) {}
  }

  @Test
  void addPrivateType() throws IOException {
    Type.add(65534, "PRIV1", Priv1Record::new);
    assertEquals("PRIV1", Type.string(65534));
    assertEquals(65534, Type.value("PRIV1"));
    Record r =
        Record.fromString(Name.fromConstantString("a."), 65534, DClass.IN, 60, "1", Name.root);
    assertTrue(r instanceof Priv1Record);
    assertEquals(1, ((Priv1Record) r).value);
  }
}
