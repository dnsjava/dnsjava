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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class EmptyRecordTest {
  @Test
  void ctor() {
    EmptyRecord ar = new EmptyRecord();
    assertNull(ar.getName());
    assertEquals(0, ar.getType());
    assertEquals(0, ar.getDClass());
    assertEquals(0, ar.getTTL());
  }

  @Test
  void rrFromWire() {
    DNSInput i = new DNSInput(new byte[] {1, 2, 3, 4, 5});
    i.jump(3);

    EmptyRecord er = new EmptyRecord();
    er.rrFromWire(i);
    assertEquals(3, i.current());
    assertNull(er.getName());
    assertEquals(0, er.getType());
    assertEquals(0, er.getDClass());
    assertEquals(0, er.getTTL());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("these are the tokens");
    EmptyRecord er = new EmptyRecord();
    er.rdataFromString(t, null);
    assertNull(er.getName());
    assertEquals(0, er.getType());
    assertEquals(0, er.getDClass());
    assertEquals(0, er.getTTL());

    assertEquals("these", t.getString());
  }

  @Test
  void rrToString() {
    EmptyRecord er = new EmptyRecord();
    assertEquals("", er.rrToString());
  }

  @Test
  void rrToWire() {
    EmptyRecord er = new EmptyRecord();
    DNSOutput out = new DNSOutput();
    er.rrToWire(out, null, true);
    assertEquals(0, out.toByteArray().length);
  }
}
