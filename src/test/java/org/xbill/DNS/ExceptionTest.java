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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class ExceptionTest {
  @Test
  void InvalidDClassException() {
    IllegalArgumentException e = new InvalidDClassException(10);
    assertEquals("Invalid DNS class: 10", e.getMessage());
  }

  @Test
  void InvalidTTLException() {
    IllegalArgumentException e = new InvalidTTLException(32345);
    assertEquals("Invalid DNS TTL: 32345", e.getMessage());
  }

  @Test
  void InvalidTypeException() {
    IllegalArgumentException e = new InvalidTypeException(32345);
    assertEquals("Invalid DNS type: 32345", e.getMessage());
  }

  @Test
  void NameTooLongException() {
    WireParseException e = new NameTooLongException();
    assertNull(e.getMessage());

    e = new NameTooLongException("This is my too long name");
    assertEquals("This is my too long name", e.getMessage());
  }

  @Test
  void RelativeNameException() throws TextParseException {
    IllegalArgumentException e = new RelativeNameException("This is my relative name");
    assertEquals("This is my relative name", e.getMessage());

    e = new RelativeNameException(Name.fromString("relative"));
    assertEquals("'relative' is not an absolute name", e.getMessage());
  }

  @Test
  void TextParseException() {
    IOException e = new TextParseException();
    assertNull(e.getMessage());

    e = new TextParseException("This is my message");
    assertEquals("This is my message", e.getMessage());
  }

  @Test
  void WireParseException() {
    IOException e = new WireParseException();
    assertNull(e.getMessage());

    e = new WireParseException("This is my message");
    assertEquals("This is my message", e.getMessage());
  }

  @Test
  void ZoneTransferException() {
    Exception e = new ZoneTransferException();
    assertNull(e.getMessage());

    e = new ZoneTransferException("This is my message");
    assertEquals("This is my message", e.getMessage());
  }
}
