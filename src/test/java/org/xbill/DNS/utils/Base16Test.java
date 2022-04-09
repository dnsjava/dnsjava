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
package org.xbill.DNS.utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class Base16Test {
  @Test
  void toString_emptyArray() {
    String out = base16.toString(new byte[0]);
    assertEquals("", out);
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "0,00", "1,01", "16,10", "255,FF",
      })
  void toString_singleByte(int b, String hex) {
    byte[] data = {(byte) b};
    String out = base16.toString(data);
    assertEquals(hex, out);
  }

  @Test
  void toString_array1() {
    byte[] data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    String out = base16.toString(data);
    assertEquals("0102030405060708090A0B0C0D0E0F", out);
  }

  @Test
  void fromString_emptyString() {
    byte[] out = base16.fromString("");
    assertEquals(0, out.length);
  }

  @Test
  void fromString_null() {
    assertNull(base16.fromString(null));
  }

  @Test
  void fromString_invalidStringLength() {
    String data = "1";
    byte[] out = base16.fromString(data);
    assertNull(out);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "0102030405060708090A0B0C0D0E0F",
        "0102030405060708090a0B0c0D0e0F",
        "010203040506070809 0a\n0B\t0c0D0e0F",
      })
  void fromString_normal(String data) {
    byte[] out = base16.fromString(data);
    byte[] exp = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    assertArrayEquals(exp, out);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "01$02@030405060708090a0B0c0D0e0F",
        "GG#!*^",
      })
  void fromString_invalid(String data) {
    byte[] out = base16.fromString(data);
    assertNull(out);
  }

  @Test
  void fromString_Utf8Bom() {
    String data = "EFBFBF";
    byte[] out = base16.fromString(data);
    assertArrayEquals(new byte[] {(byte) 0xEF, (byte) 0xBF, (byte) 0xBF}, out);
  }
}
