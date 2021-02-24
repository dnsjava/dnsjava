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
package org.xbill.DNS.utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class base64Test {
  @Test
  void toString_empty() {
    byte[] data = new byte[0];
    String out = base64.toString(data);
    assertEquals("", out);
  }

  @Test
  void toString_basic1() {
    byte[] data = {0};
    String out = base64.toString(data);
    assertEquals("AA==", out);
  }

  @Test
  void toString_basic2() {
    byte[] data = {0, 0};
    String out = base64.toString(data);
    assertEquals("AAA=", out);
  }

  @Test
  void toString_basic3() {
    byte[] data = {0, 0, 1};
    String out = base64.toString(data);
    assertEquals("AAAB", out);
  }

  @Test
  void toString_basic4() {
    byte[] data = {(byte) 0xFC, 0, 0};
    String out = base64.toString(data);
    assertEquals("/AAA", out);
  }

  @Test
  void toString_basic5() {
    byte[] data = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    String out = base64.toString(data);
    assertEquals("////", out);
  }

  @Test
  void toString_basic6() {
    byte[] data = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    String out = base64.toString(data);
    assertEquals("AQIDBAUGBwgJ", out);
  }

  @Test
  void formatString_empty1() {
    String out = base64.formatString(new byte[0], 5, "", false);
    assertEquals("", out);
  }

  @Test
  void formatString_shorter() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 13, "", false);
    assertEquals("AQIDBAUGBwgJ", out);
  }

  @Test
  void formatString_sameLength() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 12, "", false);
    assertEquals("AQIDBAUGBwgJ", out);
  }

  @Test
  void formatString_oneBreak() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 10, "", false);
    assertEquals("AQIDBAUGBw\ngJ", out);
  }

  @Test
  void formatString_twoBreaks1() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 5, "", false);
    assertEquals("AQIDB\nAUGBw\ngJ", out);
  }

  @Test
  void formatString_twoBreaks2() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 4, "", false);
    assertEquals("AQID\nBAUG\nBwgJ", out);
  }

  @Test
  void formatString_shorterWithPrefix() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 13, "!_", false);
    assertEquals("!_AQIDBAUGBwgJ", out);
  }

  @Test
  void formatString_sameLengthWithPrefix() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 12, "!_", false);
    assertEquals("!_AQIDBAUGBwgJ", out);
  }

  @Test
  void formatString_oneBreakWithPrefix() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 10, "!_", false);
    assertEquals("!_AQIDBAUGBw\n!_gJ", out);
  }

  @Test
  void formatString_twoBreaks1WithPrefix() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 5, "!_", false);
    assertEquals("!_AQIDB\n!_AUGBw\n!_gJ", out);
  }

  @Test
  void formatString_twoBreaks2WithPrefix() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 4, "!_", false);
    assertEquals("!_AQID\n!_BAUG\n!_BwgJ", out);
  }

  @Test
  void formatString_shorterWithPrefixAndClose() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 13, "!_", true);
    assertEquals("!_AQIDBAUGBwgJ )", out);
  }

  @Test
  void formatString_sameLengthWithPrefixAndClose() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 12, "!_", true);
    assertEquals("!_AQIDBAUGBwgJ )", out);
  }

  @Test
  void formatString_oneBreakWithPrefixAndClose() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 10, "!_", true);
    assertEquals("!_AQIDBAUGBw\n!_gJ )", out);
  }

  @Test
  void formatString_twoBreaks1WithPrefixAndClose() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 5, "!_", true);
    assertEquals("!_AQIDB\n!_AUGBw\n!_gJ )", out);
  }

  @Test
  void formatString_twoBreaks2WithPrefixAndClose() {
    byte[] in = {1, 2, 3, 4, 5, 6, 7, 8, 9}; // "AQIDBAUGBwgJ" (12 chars)
    String out = base64.formatString(in, 4, "!_", true);
    assertEquals("!_AQID\n!_BAUG\n!_BwgJ )", out);
  }

  @Test
  void fromString_empty1() {
    byte[] data = new byte[0];
    byte[] out = base64.fromString("");
    assertArrayEquals(new byte[0], out);
  }

  @Test
  void fromString_basic1() {
    byte[] exp = {0};
    byte[] out = base64.fromString("AA==");
    assertArrayEquals(exp, out);
  }

  @Test
  void fromString_basic2() {
    byte[] exp = {0, 0};
    byte[] out = base64.fromString("AAA=");
    assertArrayEquals(exp, out);
  }

  @Test
  void fromString_basic3() {
    byte[] exp = {0, 0, 1};
    byte[] out = base64.fromString("AAAB");
    assertArrayEquals(exp, out);
  }

  @Test
  void fromString_basic4() {
    byte[] exp = {(byte) 0xFC, 0, 0};
    byte[] out = base64.fromString("/AAA");
    assertArrayEquals(exp, out);
  }

  @Test
  void fromString_basic5() {
    byte[] exp = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    byte[] out = base64.fromString("////");
    assertArrayEquals(exp, out);
  }

  @Test
  void fromString_basic6() {
    byte[] exp = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    byte[] out = base64.fromString("AQIDBAUGBwgJ");
    assertArrayEquals(exp, out);
  }

  @Test
  void fromString_invalid1() {
    byte[] out = base64.fromString("AAA");
    assertNull(out);
  }

  @Test
  void fromString_invalid2() {
    byte[] out = base64.fromString("AA");
    assertNull(out);
  }

  @Test
  void fromString_invalid3() {
    byte[] out = base64.fromString("A");
    assertNull(out);
  }

  @Test
  void fromString_invalid4() {
    byte[] out = base64.fromString("BB==");
    assertNull(out);
  }

  @Test
  void fromString_invalid5() {
    byte[] out = base64.fromString("BBB=");
    assertNull(out);
  }
}
