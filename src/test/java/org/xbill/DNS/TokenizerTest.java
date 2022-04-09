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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class TokenizerTest {
  @Test
  void get() throws IOException {
    Tokenizer t =
        new Tokenizer(
            new BufferedInputStream(
                new ByteArrayInputStream(
                    "AnIdentifier \"a quoted \\\" string\"\r\n; this is \"my\"\t(comment)\nanotherIdentifier (\ramultilineIdentifier\n)"
                        .getBytes())));

    Tokenizer.Token tt = t.get(true, true);
    assertEquals(Tokenizer.IDENTIFIER, tt.type());
    assertTrue(tt.isString());
    assertFalse(tt.isEOL());
    assertEquals("AnIdentifier", tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.WHITESPACE, tt.type());
    assertFalse(tt.isString());
    assertFalse(tt.isEOL());
    assertNull(tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.QUOTED_STRING, tt.type());
    assertTrue(tt.isString());
    assertFalse(tt.isEOL());
    assertEquals("a quoted \\\" string", tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.EOL, tt.type());
    assertFalse(tt.isString());
    assertTrue(tt.isEOL());
    assertNull(tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.COMMENT, tt.type());
    assertFalse(tt.isString());
    assertFalse(tt.isEOL());
    assertEquals(" this is \"my\"\t(comment)", tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.EOL, tt.type());
    assertFalse(tt.isString());
    assertTrue(tt.isEOL());
    assertNull(tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.IDENTIFIER, tt.type());
    assertTrue(tt.isString());
    assertFalse(tt.isEOL());
    assertEquals("anotherIdentifier", tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.WHITESPACE, tt.type());

    tt = t.get(true, true);
    assertEquals(Tokenizer.IDENTIFIER, tt.type());
    assertTrue(tt.isString());
    assertFalse(tt.isEOL());
    assertEquals("amultilineIdentifier", tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.WHITESPACE, tt.type());

    tt = t.get(true, true);
    assertEquals(Tokenizer.EOF, tt.type());
    assertFalse(tt.isString());
    assertTrue(tt.isEOL());
    assertNull(tt.value());

    // should be able to do this repeatedly
    tt = t.get(true, true);
    assertEquals(Tokenizer.EOF, tt.type());
    assertFalse(tt.isString());
    assertTrue(tt.isEOL());
    assertNull(tt.value());

    t = new Tokenizer("onlyOneIdentifier");
    tt = t.get();
    assertEquals(Tokenizer.IDENTIFIER, tt.type());
    assertEquals("onlyOneIdentifier", tt.value());

    t = new Tokenizer("identifier ;");
    tt = t.get();
    assertEquals("identifier", tt.value());
    tt = t.get();
    assertEquals(Tokenizer.EOF, tt.type());

    // some ungets
    t = new Tokenizer("identifier \nidentifier2; junk comment");
    tt = t.get(true, true);
    assertEquals(Tokenizer.IDENTIFIER, tt.type());
    assertEquals("identifier", tt.value());

    t.unget();

    tt = t.get(true, true);
    assertEquals(Tokenizer.IDENTIFIER, tt.type());
    assertEquals("identifier", tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.WHITESPACE, tt.type());

    t.unget();
    tt = t.get(true, true);
    assertEquals(Tokenizer.WHITESPACE, tt.type());

    tt = t.get(true, true);
    assertEquals(Tokenizer.EOL, tt.type());

    t.unget();
    tt = t.get(true, true);
    assertEquals(Tokenizer.EOL, tt.type());

    tt = t.get(true, true);
    assertEquals(Tokenizer.IDENTIFIER, tt.type());
    assertEquals("identifier2", tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.COMMENT, tt.type());
    assertEquals(" junk comment", tt.value());

    t.unget();
    tt = t.get(true, true);
    assertEquals(Tokenizer.COMMENT, tt.type());
    assertEquals(" junk comment", tt.value());

    tt = t.get(true, true);
    assertEquals(Tokenizer.EOF, tt.type());

    t = new Tokenizer("identifier ( junk ; comment\n )");
    tt = t.get();
    assertEquals(Tokenizer.IDENTIFIER, tt.type());
    assertEquals(Tokenizer.IDENTIFIER, t.get().type());
    assertEquals(Tokenizer.EOF, t.get().type());
  }

  @Test
  void get_invalidIncomplete() throws IOException {
    try (Tokenizer t = new Tokenizer("(this ;")) {
      t.get();
      assertThrows(TextParseException.class, t::get);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "\"bad", ")", "\\", "\"\n",
      })
  void get_invalid(String data) {
    try (Tokenizer t = new Tokenizer(data)) {
      assertThrows(TextParseException.class, t::get);
    }
  }

  @Test
  void file_input() throws IOException {
    File tmp = File.createTempFile("dnsjava", "tmp");
    Files.write(tmp.toPath(), "file\ninput; test".getBytes(StandardCharsets.UTF_8));
    try (Tokenizer t = new Tokenizer(tmp)) {
      Tokenizer.Token tt = t.get();
      assertEquals(Tokenizer.IDENTIFIER, tt.type());
      assertEquals("file", tt.value());

      tt = t.get();
      assertEquals(Tokenizer.EOL, tt.type());

      tt = t.get();
      assertEquals(Tokenizer.IDENTIFIER, tt.type());
      assertEquals("input", tt.value());

      tt = t.get(false, true);
      assertEquals(Tokenizer.COMMENT, tt.type());
      assertEquals(" test", tt.value());
    } finally {
      tmp.delete();
    }
  }

  @Test
  void unwanted_comment() throws IOException {
    Tokenizer t = new Tokenizer("; this whole thing is a comment\n");
    Tokenizer.Token tt = t.get();

    assertEquals(Tokenizer.EOL, tt.type());
  }

  @Test
  void unwanted_ungotten_whitespace() throws IOException {
    Tokenizer t = new Tokenizer(" ");
    t.get(true, true);
    t.unget();
    Tokenizer.Token tt = t.get();
    assertEquals(Tokenizer.EOF, tt.type());
  }

  @Test
  void unwanted_ungotten_comment() throws IOException {
    Tokenizer t = new Tokenizer("; this whole thing is a comment");
    t.get(true, true);
    t.unget();
    Tokenizer.Token tt = t.get();
    assertEquals(Tokenizer.EOF, tt.type());
  }

  @Test
  void empty_string() throws IOException {
    Tokenizer t = new Tokenizer("");
    Tokenizer.Token tt = t.get();
    assertEquals(Tokenizer.EOF, tt.type());

    t = new Tokenizer(" ");
    tt = t.get();
    assertEquals(Tokenizer.EOF, tt.type());
  }

  @Test
  void multiple_ungets() throws IOException {
    Tokenizer t = new Tokenizer("a simple one");
    t.get();
    t.unget();
    assertThrows(IllegalStateException.class, t::unget);
  }

  @Test
  void getStringIdentifier() throws IOException {
    Tokenizer t = new Tokenizer("just_an_identifier");
    assertEquals("just_an_identifier", t.getString());
  }

  @Test
  void getStringQuoted() throws IOException {
    Tokenizer t = new Tokenizer("\"just a string\"");
    assertEquals("just a string", t.getString());
  }

  @Test
  void getStringComment() {
    Tokenizer t = new Tokenizer("; just a comment");
    assertThrows(TextParseException.class, t::getString);
  }

  @Test
  void getIdentifier() throws IOException {
    Tokenizer t = new Tokenizer("just_an_identifier");
    String out = t.getIdentifier();
    assertEquals("just_an_identifier", out);

    t = new Tokenizer("\"just a string\"");
    assertThrows(TextParseException.class, t::getIdentifier);
  }

  @Test
  void getLong() throws IOException {
    Tokenizer t = new Tokenizer((Integer.MAX_VALUE + 1L) + "");
    long out = t.getLong();
    assertEquals(Integer.MAX_VALUE + 1L, out);

    t = new Tokenizer("-10");
    assertThrows(TextParseException.class, t::getLong);

    t = new Tokenizer("19_identifier");
    assertThrows(TextParseException.class, t::getLong);
  }

  @Test
  void getUInt32() throws IOException {
    Tokenizer t = new Tokenizer(0xABCDEF12L + "");
    long out = t.getUInt32();
    assertEquals(0xABCDEF12L, out);

    t = new Tokenizer(0x100000000L + "");
    assertThrows(TextParseException.class, t::getUInt32);

    t = new Tokenizer("-12345");
    assertThrows(TextParseException.class, t::getUInt32);
  }

  @Test
  void getUInt16() throws IOException {
    Tokenizer t = new Tokenizer(0xABCDL + "");
    int out = t.getUInt16();
    assertEquals(0xABCDL, out);

    t = new Tokenizer(0x10000 + "");
    assertThrows(TextParseException.class, t::getUInt16);

    t = new Tokenizer("-125");
    assertThrows(TextParseException.class, t::getUInt16);
  }

  @Test
  void getUInt8() throws IOException {
    Tokenizer t = new Tokenizer(0xCDL + "");
    int out = t.getUInt8();
    assertEquals(0xCDL, out);

    t = new Tokenizer(0x100 + "");
    assertThrows(TextParseException.class, t::getUInt8);

    t = new Tokenizer("-12");
    assertThrows(TextParseException.class, t::getUInt8);
  }

  @Test
  void getTTL() throws IOException {
    Tokenizer t = new Tokenizer("59S");
    assertEquals(59, t.getTTL());

    t = new Tokenizer(TTL.MAX_VALUE + "");
    assertEquals(TTL.MAX_VALUE, t.getTTL());

    t = new Tokenizer((TTL.MAX_VALUE + 1L) + "");
    assertEquals(TTL.MAX_VALUE, t.getTTL());

    t = new Tokenizer("Junk");
    assertThrows(TextParseException.class, t::getTTL);
  }

  @Test
  void getTTLLike() throws IOException {
    Tokenizer t = new Tokenizer("59S");
    assertEquals(59, t.getTTLLike());

    t = new Tokenizer(TTL.MAX_VALUE + "");
    assertEquals(TTL.MAX_VALUE, t.getTTLLike());

    t = new Tokenizer((TTL.MAX_VALUE + 1L) + "");
    assertEquals(TTL.MAX_VALUE + 1L, t.getTTLLike());

    t = new Tokenizer("Junk");
    assertThrows(TextParseException.class, t::getTTLLike);
  }

  @Test
  void getName() throws IOException {
    Tokenizer t = new Tokenizer("junk");
    Name exp = Name.fromString("junk.");
    Name out = t.getName(Name.root);
    assertEquals(exp, out);
  }

  @Test
  void getNameRelative() throws IOException {
    Name rel = Name.fromString("you.dig");
    Tokenizer t = new Tokenizer("junk");
    assertThrows(RelativeNameException.class, () -> t.getName(rel));
  }

  @Test
  void getNameFromEmpty() {
    Tokenizer t = new Tokenizer("");
    assertThrows(TextParseException.class, () -> t.getName(Name.root));
  }

  @Test
  void getEOL() throws IOException {
    Tokenizer t = new Tokenizer("id");
    t.getIdentifier();
    try {
      t.getEOL();
    } catch (TextParseException e) {
      fail(e.getMessage());
    }

    t = new Tokenizer("\n");
    try {
      t.getEOL();
      t.getEOL();
    } catch (TextParseException e) {
      fail(e.getMessage());
    }

    t = new Tokenizer("id");
    assertThrows(TextParseException.class, t::getEOL);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        // basic
        "AQIDBAUGBwgJ",
        // with some whitespace
        "AQIDB AUGB   wgJ",
        // two base64s separated by newline
        "AQIDBAUGBwgJ\nAB23DK",
      })
  void getBase64(String data) throws IOException {
    byte[] exp = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    Tokenizer t = new Tokenizer(data);
    byte[] out = t.getBase64();
    assertArrayEquals(exp, out);
  }

  @Test
  void getBase64Newline() throws IOException {
    // no remaining strings
    Tokenizer t = new Tokenizer("\n");
    assertNull(t.getBase64());
  }

  @Test
  void getBase64NewlineRequired() {
    Tokenizer t = new Tokenizer("\n");
    assertThrows(TextParseException.class, () -> t.getBase64(true));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void getBase64InvalidEncoding(boolean required) {
    Tokenizer t = new Tokenizer("not_base64");
    assertThrows(TextParseException.class, () -> t.getBase64(required));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        // basic
        "0102030405060708090A0B0C0D0E0F",
        // with some whitespace
        "0102030 405 060708090A0B0C      0D0E0F",
        // two hexs separated by newline
        "0102030405060708090A0B0C0D0E0F\n01AB3FE",
      },
      ignoreLeadingAndTrailingWhitespace = false)
  void getHex(String data) throws IOException {
    byte[] exp = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    Tokenizer t = new Tokenizer(data);
    byte[] out = t.getHex();
    assertArrayEquals(exp, out);
  }

  @Test
  void getHexNewline() throws IOException {
    // no remaining strings
    Tokenizer t = new Tokenizer("\n");
    assertNull(t.getHex());
  }

  @Test
  void getHexNewlineRequired() {
    Tokenizer t = new Tokenizer("\n");
    assertThrows(TextParseException.class, () -> t.getHex(true));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void getHexInvalidEncoding(boolean required) {
    Tokenizer t = new Tokenizer("not_hex");
    assertThrows(TextParseException.class, () -> t.getHex(required));
  }
}
