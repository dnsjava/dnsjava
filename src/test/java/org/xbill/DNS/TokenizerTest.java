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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

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
    assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
    assertThat(tt.isString()).isTrue();
    assertThat(tt.isEOL()).isFalse();
    assertThat(tt.value()).isEqualTo("AnIdentifier");

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.WHITESPACE);
    assertThat(tt.isString()).isFalse();
    assertThat(tt.isEOL()).isFalse();
    assertThat(tt.value()).isNull();

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.QUOTED_STRING);
    assertThat(tt.isString()).isTrue();
    assertThat(tt.isEOL()).isFalse();
    assertThat(tt.value()).isEqualTo("a quoted \\\" string");

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.EOL);
    assertThat(tt.isString()).isFalse();
    assertThat(tt.isEOL()).isTrue();
    assertThat(tt.value()).isNull();

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.COMMENT);
    assertThat(tt.isString()).isFalse();
    assertThat(tt.isEOL()).isFalse();
    assertThat(tt.value()).isEqualTo(" this is \"my\"\t(comment)");

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.EOL);
    assertThat(tt.isString()).isFalse();
    assertThat(tt.isEOL()).isTrue();
    assertThat(tt.value()).isNull();

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
    assertThat(tt.isString()).isTrue();
    assertThat(tt.isEOL()).isFalse();
    assertThat(tt.value()).isEqualTo("anotherIdentifier");

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.WHITESPACE);

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
    assertThat(tt.isString()).isTrue();
    assertThat(tt.isEOL()).isFalse();
    assertThat(tt.value()).isEqualTo("amultilineIdentifier");

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.WHITESPACE);

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.EOF);
    assertThat(tt.isString()).isFalse();
    assertThat(tt.isEOL()).isTrue();
    assertThat(tt.value()).isNull();

    // should be able to do this repeatedly
    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.EOF);
    assertThat(tt.isString()).isFalse();
    assertThat(tt.isEOL()).isTrue();
    assertThat(tt.value()).isNull();

    t = new Tokenizer("onlyOneIdentifier");
    tt = t.get();
    assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
    assertThat(tt.value()).isEqualTo("onlyOneIdentifier");

    t = new Tokenizer("identifier ;");
    tt = t.get();
    assertThat(tt.value()).isEqualTo("identifier");
    tt = t.get();
    assertThat(tt.type()).isEqualTo(Tokenizer.EOF);

    // some ungets
    t = new Tokenizer("identifier \nidentifier2; junk comment");
    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
    assertThat(tt.value()).isEqualTo("identifier");

    t.unget();

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
    assertThat(tt.value()).isEqualTo("identifier");

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.WHITESPACE);

    t.unget();
    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.WHITESPACE);

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.EOL);

    t.unget();
    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.EOL);

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
    assertThat(tt.value()).isEqualTo("identifier2");

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.COMMENT);
    assertThat(tt.value()).isEqualTo(" junk comment");

    t.unget();
    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.COMMENT);
    assertThat(tt.value()).isEqualTo(" junk comment");

    tt = t.get(true, true);
    assertThat(tt.type()).isEqualTo(Tokenizer.EOF);

    t = new Tokenizer("identifier ( junk ; comment\n )");
    tt = t.get();
    assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
    assertThat(t.get().type()).isEqualTo(Tokenizer.IDENTIFIER);
    assertThat(t.get().type()).isEqualTo(Tokenizer.EOF);
  }

  @Test
  void get_invalidIncomplete() throws IOException {
    try (Tokenizer t = new Tokenizer("(this ;")) {
      t.get();
      assertThatExceptionOfType(TextParseException.class).isThrownBy(t::get);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "\"bad", ")", "\\", "\"\n",
      })
  void get_invalid(String data) {
    try (Tokenizer t = new Tokenizer(data)) {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(t::get);
    }
  }

  @Test
  void file_input() throws IOException {
    File tmp = File.createTempFile("dnsjava", "tmp");
    Files.write(tmp.toPath(), "file\ninput; test".getBytes(StandardCharsets.UTF_8));
    try (Tokenizer t = new Tokenizer(tmp)) {
      Tokenizer.Token tt = t.get();
      assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
      assertThat(tt.value()).isEqualTo("file");

      tt = t.get();
      assertThat(tt.type()).isEqualTo(Tokenizer.EOL);

      tt = t.get();
      assertThat(tt.type()).isEqualTo(Tokenizer.IDENTIFIER);
      assertThat(tt.value()).isEqualTo("input");

      tt = t.get(false, true);
      assertThat(tt.type()).isEqualTo(Tokenizer.COMMENT);
      assertThat(tt.value()).isEqualTo(" test");
    } finally {
      tmp.delete();
    }
  }

  @Test
  void unwanted_comment() throws IOException {
    Tokenizer t = new Tokenizer("; this whole thing is a comment\n");
    Tokenizer.Token tt = t.get();

    assertThat(tt.type()).isEqualTo(Tokenizer.EOL);
  }

  @Test
  void unwanted_ungotten_whitespace() throws IOException {
    Tokenizer t = new Tokenizer(" ");
    t.get(true, true);
    t.unget();
    Tokenizer.Token tt = t.get();
    assertThat(tt.type()).isEqualTo(Tokenizer.EOF);
  }

  @Test
  void unwanted_ungotten_comment() throws IOException {
    Tokenizer t = new Tokenizer("; this whole thing is a comment");
    t.get(true, true);
    t.unget();
    Tokenizer.Token tt = t.get();
    assertThat(tt.type()).isEqualTo(Tokenizer.EOF);
  }

  @Test
  void empty_string() throws IOException {
    Tokenizer t = new Tokenizer("");
    Tokenizer.Token tt = t.get();
    assertThat(tt.type()).isEqualTo(Tokenizer.EOF);

    t = new Tokenizer(" ");
    tt = t.get();
    assertThat(tt.type()).isEqualTo(Tokenizer.EOF);
  }

  @Test
  void multiple_ungets() throws IOException {
    Tokenizer t = new Tokenizer("a simple one");
    t.get();
    t.unget();
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(t::unget);
  }

  @Test
  void getStringIdentifier() throws IOException {
    Tokenizer t = new Tokenizer("just_an_identifier");
    assertThat(t.getString()).isEqualTo("just_an_identifier");
  }

  @Test
  void getStringQuoted() throws IOException {
    Tokenizer t = new Tokenizer("\"just a string\"");
    assertThat(t.getString()).isEqualTo("just a string");
  }

  @Test
  void getStringComment() {
    Tokenizer t = new Tokenizer("; just a comment");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getString);
  }

  @Test
  void getIdentifier() throws IOException {
    Tokenizer t = new Tokenizer("just_an_identifier");
    String out = t.getIdentifier();
    assertThat(out).isEqualTo("just_an_identifier");

    t = new Tokenizer("\"just a string\"");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getIdentifier);
  }

  @Test
  void getLong() throws IOException {
    Tokenizer t = new Tokenizer((Integer.MAX_VALUE + 1L) + "");
    long out = t.getLong();
    assertThat(out).isEqualTo(Integer.MAX_VALUE + 1L);

    t = new Tokenizer("-10");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getLong);

    t = new Tokenizer("19_identifier");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getLong);
  }

  @Test
  void getUInt32() throws IOException {
    Tokenizer t = new Tokenizer(0xABCDEF12L + "");
    long out = t.getUInt32();
    assertThat(out).isEqualTo(0xABCDEF12L);

    t = new Tokenizer(0x100000000L + "");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getUInt32);

    t = new Tokenizer("-12345");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getUInt32);
  }

  @Test
  void getUInt16() throws IOException {
    Tokenizer t = new Tokenizer(0xABCDL + "");
    int out = t.getUInt16();
    assertThat(out).isEqualTo(0xABCDL);

    t = new Tokenizer(0x10000 + "");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getUInt16);

    t = new Tokenizer("-125");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getUInt16);
  }

  @Test
  void getUInt8() throws IOException {
    Tokenizer t = new Tokenizer(0xCDL + "");
    int out = t.getUInt8();
    assertThat(out).isEqualTo(0xCDL);

    t = new Tokenizer(0x100 + "");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getUInt8);

    t = new Tokenizer("-12");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getUInt8);
  }

  @Test
  void getTTL() throws IOException {
    Tokenizer t = new Tokenizer("59S");
    assertThat(t.getTTL()).isEqualTo(59);

    t = new Tokenizer(TTL.MAX_VALUE + "");
    assertThat(t.getTTL()).isEqualTo(TTL.MAX_VALUE);

    t = new Tokenizer((TTL.MAX_VALUE + 1L) + "");
    assertThat(t.getTTL()).isEqualTo(TTL.MAX_VALUE);

    t = new Tokenizer("Junk");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getTTL);
  }

  @Test
  void getTTLLike() throws IOException {
    Tokenizer t = new Tokenizer("59S");
    assertThat(t.getTTLLike()).isEqualTo(59);

    t = new Tokenizer(TTL.MAX_VALUE + "");
    assertThat(t.getTTLLike()).isEqualTo(TTL.MAX_VALUE);

    t = new Tokenizer((TTL.MAX_VALUE + 1L) + "");
    assertThat(t.getTTLLike()).isEqualTo(TTL.MAX_VALUE + 1L);

    t = new Tokenizer("Junk");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t::getTTLLike);
  }

  @Test
  void getName() throws IOException {
    Tokenizer t = new Tokenizer("junk");
    Name exp = Name.fromString("junk.");
    Name out = t.getName(Name.root);
    assertThat(out).isEqualTo(exp);
  }

  @Test
  void getNameRelative() throws IOException {
    Name rel = Name.fromString("you.dig");
    Tokenizer t = new Tokenizer("junk");
    assertThatExceptionOfType(RelativeNameException.class).isThrownBy(() -> t.getName(rel));
  }

  @Test
  void getNameFromEmpty() {
    Tokenizer t = new Tokenizer("");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> t.getName(Name.root));
  }

  @Test
  void getEOL() throws IOException {
    Tokenizer t = new Tokenizer("id");
    t.getIdentifier();
    assertThatCode(t::getEOL).doesNotThrowAnyException();

    Tokenizer t2 = new Tokenizer("\n");
    assertThatCode(
            () -> {
              t2.getEOL();
              t2.getEOL();
            })
        .doesNotThrowAnyException();

    Tokenizer t3 = new Tokenizer("id");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(t3::getEOL);
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
    assertThat(out).containsExactly(exp);
  }

  @Test
  void getBase64Newline() throws IOException {
    // no remaining strings
    Tokenizer t = new Tokenizer("\n");
    assertThat(t.getBase64()).isNull();
  }

  @Test
  void getBase64NewlineRequired() {
    Tokenizer t = new Tokenizer("\n");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> t.getBase64(true));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void getBase64InvalidEncoding(boolean required) {
    Tokenizer t = new Tokenizer("not_base64");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> t.getBase64(required));
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
    assertThat(out).containsExactly(exp);
  }

  @Test
  void getHexNewline() throws IOException {
    // no remaining strings
    Tokenizer t = new Tokenizer("\n");
    assertThat(t.getHex()).isNull();
  }

  @Test
  void getHexNewlineRequired() {
    Tokenizer t = new Tokenizer("\n");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> t.getHex(true));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void getHexInvalidEncoding(boolean required) {
    Tokenizer t = new Tokenizer("not_hex");
    assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> t.getHex(required));
  }
}
