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

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.io.IOException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class NameTest {
  @Nested
  class Test_String_init {
    private final String m_abs = "WWW.DnsJava.org.";
    private Name m_abs_origin;
    private final String m_rel = "WWW.DnsJava";
    private Name m_rel_origin;

    @BeforeEach
    void setUp() throws TextParseException {
      m_abs_origin = Name.fromString("Orig.");
      m_rel_origin = Name.fromString("Orig");
    }

    @Test
    void ctor_empty() {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> new Name(""));
    }

    @Test
    void ctor_at_null_origin() throws TextParseException {
      Name n = new Name("@");
      assertThat(n.isAbsolute()).isFalse();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isZero();
      assertThat(n.length()).isZero();
    }

    @Test
    void ctor_at_abs_origin() throws TextParseException {
      Name n = new Name("@", m_abs_origin);
      assertThat(n).isEqualTo(m_abs_origin);
    }

    @Test
    void ctor_at_rel_origin() throws TextParseException {
      Name n = new Name("@", m_rel_origin);
      assertThat(n).isEqualTo(m_rel_origin);
    }

    @Test
    void ctor_dot() throws TextParseException {
      Name n = new Name(".");
      assertThat(n).isEqualTo(Name.root);
      assertNotSame(Name.root, n);
      assertThat(n.labels()).isOne();
      assertThat(n.length()).isOne();
    }

    @Test
    void ctor_wildcard() throws TextParseException {
      Name n = new Name("*");
      assertThat(n.isAbsolute()).isFalse();
      assertThat(n.isWild()).isTrue();
      assertThat(n.labels()).isOne();
      assertThat(n.length()).isEqualTo((short) 2);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {1, '*'});
      assertThat(n.getLabelString(0)).isEqualTo("*");
    }

    @Test
    void ctor_abs() throws TextParseException {
      Name n = new Name(m_abs);
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(4);
      assertThat(n.length()).isEqualTo((short) 17);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {3, 'W', 'W', 'W'});
      assertThat(n.getLabelString(0)).isEqualTo("WWW");
      assertThat(n.getLabel(1)).containsExactly(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'});
      assertThat(n.getLabelString(1)).isEqualTo("DnsJava");
      assertThat(n.getLabel(2)).containsExactly(new byte[] {3, 'o', 'r', 'g'});
      assertThat(n.getLabelString(2)).isEqualTo("org");
      assertThat(n.getLabel(3)).containsExactly(new byte[] {0});
      assertThat(n.getLabelString(3)).isEmpty();
    }

    @Test
    void ctor_rel() throws TextParseException {
      Name n = new Name(m_rel);
      assertThat(n.isAbsolute()).isFalse();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(2);
      assertThat(n.length()).isEqualTo((short) 12);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {3, 'W', 'W', 'W'});
      assertThat(n.getLabelString(0)).isEqualTo("WWW");
      assertThat(n.getLabel(1)).containsExactly(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'});
      assertThat(n.getLabelString(1)).isEqualTo("DnsJava");
    }

    @Test
    void ctor_9label() throws TextParseException {
      // 9 is the number of label positions that are cached
      Name n = new Name("a.b.c.d.e.f.g.h.");
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(9);
      assertThat(n.length()).isEqualTo((short) 17);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {1, 'a'});
      assertThat(n.getLabelString(0)).isEqualTo("a");
      assertThat(n.getLabel(1)).containsExactly(new byte[] {1, 'b'});
      assertThat(n.getLabelString(1)).isEqualTo("b");
      assertThat(n.getLabel(2)).containsExactly(new byte[] {1, 'c'});
      assertThat(n.getLabelString(2)).isEqualTo("c");
      assertThat(n.getLabel(3)).containsExactly(new byte[] {1, 'd'});
      assertThat(n.getLabelString(3)).isEqualTo("d");
      assertThat(n.getLabel(4)).containsExactly(new byte[] {1, 'e'});
      assertThat(n.getLabelString(4)).isEqualTo("e");
      assertThat(n.getLabel(5)).containsExactly(new byte[] {1, 'f'});
      assertThat(n.getLabelString(5)).isEqualTo("f");
      assertThat(n.getLabel(6)).containsExactly(new byte[] {1, 'g'});
      assertThat(n.getLabelString(6)).isEqualTo("g");
      assertThat(n.getLabel(7)).containsExactly(new byte[] {1, 'h'});
      assertThat(n.getLabelString(7)).isEqualTo("h");
      assertThat(n.getLabel(8)).containsExactly(new byte[] {0});
      assertThat(n.getLabelString(8)).isEmpty();
    }

    @Test
    void ctor_10label() throws TextParseException {
      // 9 is the number of label positions that are cached
      Name n = new Name("a.b.c.d.e.f.g.h.i.");
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(10);
      assertThat(n.length()).isEqualTo((short) 19);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {1, 'a'});
      assertThat(n.getLabelString(0)).isEqualTo("a");
      assertThat(n.getLabel(1)).containsExactly(new byte[] {1, 'b'});
      assertThat(n.getLabelString(1)).isEqualTo("b");
      assertThat(n.getLabel(2)).containsExactly(new byte[] {1, 'c'});
      assertThat(n.getLabelString(2)).isEqualTo("c");
      assertThat(n.getLabel(3)).containsExactly(new byte[] {1, 'd'});
      assertThat(n.getLabelString(3)).isEqualTo("d");
      assertThat(n.getLabel(4)).containsExactly(new byte[] {1, 'e'});
      assertThat(n.getLabelString(4)).isEqualTo("e");
      assertThat(n.getLabel(5)).containsExactly(new byte[] {1, 'f'});
      assertThat(n.getLabelString(5)).isEqualTo("f");
      assertThat(n.getLabel(6)).containsExactly(new byte[] {1, 'g'});
      assertThat(n.getLabelString(6)).isEqualTo("g");
      assertThat(n.getLabel(7)).containsExactly(new byte[] {1, 'h'});
      assertThat(n.getLabelString(7)).isEqualTo("h");
      assertThat(n.getLabel(8)).containsExactly(new byte[] {1, 'i'});
      assertThat(n.getLabelString(8)).isEqualTo("i");
      assertThat(n.getLabel(9)).containsExactly(new byte[] {0});
      assertThat(n.getLabelString(9)).isEmpty();
    }

    @Test
    void ctor_removed_label() throws TextParseException, NameTooLongException {
      String pre = "prepend";
      Name stripped = new Name(Name.fromString("sub.domain.example."), 1);
      Name concat = new Name(pre, stripped);
      assertThat(concat)
          .isEqualTo(Name.concatenate(Name.fromString(pre), stripped))
          .isEqualTo(Name.fromString(pre, stripped))
          .hasToString("prepend.domain.example.");
    }

    @Test
    void ctor_removed_label_multiple() throws TextParseException {
      Name two = Name.fromString("sub1.sub2.example.com.");
      Name one = new Name(two, 1);
      Name domain = new Name(one, 1);
      Name tld = new Name(domain, 1);
      Name root = new Name(tld, 1);
      assertThat(one).isEqualTo(Name.fromString("sub2.example.com."));
      assertThat(domain).isEqualTo(Name.fromString("example.com."));
      assertThat(new Name(two, 2)).isEqualTo(Name.fromString("example.com."));
      assertThat(tld).isEqualTo(Name.fromString("com."));
      assertThat(new Name(two, 3)).isEqualTo(Name.fromString("com."));
      assertThat(root).isEqualTo(Name.root);
      assertThat(new Name(two, 4)).isEqualTo(Name.root);
    }

    @Test
    void ctor_abs_abs_origin() throws TextParseException {
      Name n = new Name(m_abs, m_abs_origin);
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(4);
      assertThat(n.length()).isEqualTo((short) 17);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {3, 'W', 'W', 'W'});
      assertThat(n.getLabelString(0)).isEqualTo("WWW");
      assertThat(n.getLabel(1)).containsExactly(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'});
      assertThat(n.getLabelString(1)).isEqualTo("DnsJava");
      assertThat(n.getLabel(2)).containsExactly(new byte[] {3, 'o', 'r', 'g'});
      assertThat(n.getLabelString(2)).isEqualTo("org");
      assertThat(n.getLabel(3)).containsExactly(new byte[] {0});
      assertThat(n.getLabelString(3)).isEmpty();
    }

    @Test
    void ctor_abs_rel_origin() throws TextParseException {
      Name n = new Name(m_abs, m_rel_origin);
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(4);
      assertThat(n.length()).isEqualTo((short) 17);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {3, 'W', 'W', 'W'});
      assertThat(n.getLabelString(0)).isEqualTo("WWW");
      assertThat(n.getLabel(1)).containsExactly(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'});
      assertThat(n.getLabelString(1)).isEqualTo("DnsJava");
      assertThat(n.getLabel(2)).containsExactly(new byte[] {3, 'o', 'r', 'g'});
      assertThat(n.getLabelString(2)).isEqualTo("org");
      assertThat(n.getLabel(3)).containsExactly(new byte[] {0});
      assertThat(n.getLabelString(3)).isEmpty();
    }

    @Test
    void ctor_rel_abs_origin() throws TextParseException {
      Name n = new Name(m_rel, m_abs_origin);
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(4);
      assertThat(n.length()).isEqualTo((short) 18);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {3, 'W', 'W', 'W'});
      assertThat(n.getLabelString(0)).isEqualTo("WWW");
      assertThat(n.getLabel(1)).containsExactly(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'});
      assertThat(n.getLabelString(1)).isEqualTo("DnsJava");
      assertThat(n.getLabel(2)).containsExactly(new byte[] {4, 'O', 'r', 'i', 'g'});
      assertThat(n.getLabelString(2)).isEqualTo("Orig");
      assertThat(n.getLabel(3)).containsExactly(new byte[] {0});
      assertThat(n.getLabelString(3)).isEmpty();
    }

    @Test
    void ctor_invalid_label() {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> new Name("junk..junk."));
    }

    @Test
    void ctor_max_label() throws TextParseException {
      // name with a 63 char label
      Name n = new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.");
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(3);
      assertThat(n.length()).isEqualTo((short) 67);
      assertThat(n.getLabel(0))
          .containsExactly(
              new byte[] {
                63, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'
              });
      assertThat(n.getLabelString(0))
          .isEqualTo("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
      assertThat(n.getLabel(1)).containsExactly(new byte[] {1, 'b'});
      assertThat(n.getLabelString(1)).isEqualTo("b");
      assertThat(n.getLabel(2)).containsExactly(new byte[] {0});
      assertThat(n.getLabelString(2)).isEmpty();
    }

    @Test
    void ctor_toobig_label() {
      // name with a 64 char label
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(
              () ->
                  new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b."));
    }

    @Test
    void ctor_length_too_long_rel() {
      // We want to fail to crate this as there is no way to make a Name that long absolute,
      // which means that it can not be used for lookups or updates.
      String label63 = IntStream.range(0, 63).mapToObj(i -> "a").collect(Collectors.joining());
      String label62 = IntStream.range(0, 62).mapToObj(i -> "a").collect(Collectors.joining());
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> new Name(format("%s.%s.%s.%s", label63, label63, label63, label62)));
    }

    @Test
    void ctor_longest_allowed_rel() throws TextParseException {
      // relative name with three 63-char labels and a 61-char label
      Name n =
          new Name(
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
      assertThat(n.isAbsolute()).isFalse();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(4);
      assertThat(n.length()).isEqualTo((short) 254);
    }

    @Test
    void ctor_max_length_abs() throws TextParseException {
      // absolute name with three 63-char labels and a 61-char label
      Name n =
          new Name(
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.");
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(5);
      assertThat(n.length()).isEqualTo((short) 255);
    }

    @Test
    void ctor_max_length_rel_with_root_origin() throws TextParseException {
      // relative name with three 63-char labels and a 61-char label with Name.root as origin
      Name n =
          new Name(
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
              Name.root);
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(5);
      assertThat(n.length()).isEqualTo((short) 255);
    }

    @Test
    void ctor_max_length_rel_with_abs_origin() throws TextParseException {
      // relative name with three 63-char labels and a 52-char label with 9-char absolute name as
      // origin
      Name n =
          new Name(
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.dddddddddddddddddddddddddddddddddddddddddddddddddddd",
              Name.fromString("absolute."));
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(6);
      assertThat(n.length()).isEqualTo((short) 255);
    }

    @Test
    void ctor_too_long_rel_with_rel_origin() {
      // relative name with three 63-char labels and a 53-char label with an 8-char relative origin
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(
              () ->
                  new Name(
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                      Name.fromConstantString("relative")));
    }

    @Test
    void ctor_too_long_rel_with_abs_origin() {
      // relative name with three 63-char labels and a 53-char label with a 9-char absolute origin
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(
              () ->
                  new Name(
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                      Name.fromConstantString("absolute.")));
    }

    @Test
    void ctor_escaped() throws TextParseException {
      Name n = new Name("ab\\123cd");
      assertThat(n.isAbsolute()).isFalse();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isOne();
      assertThat(n.length()).isEqualTo((short) 6);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {5, 'a', 'b', (byte) 123, 'c', 'd'});
    }

    @Test
    void ctor_escaped_end() throws TextParseException {
      Name n = new Name("abcd\\123");
      assertThat(n.isAbsolute()).isFalse();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isOne();
      assertThat(n.length()).isEqualTo((short) 6);
      assertThat(n.getLabel(0)).containsExactly(new byte[] {5, 'a', 'b', 'c', 'd', (byte) 123});
    }

    @Test
    void ctor_short_escaped_one() {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> new Name("ab\\1cd"));
    }

    @Test
    void ctor_short_escaped_two() {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> new Name("ab\\12cd"));
    }

    @Test
    void ctor_short_escaped_end() {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> new Name("ab\\12"));
    }

    @Test
    void ctor_empty_escaped_end() {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> new Name("ab\\"));
    }

    @Test
    void ctor_toobig_escaped() {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> new Name("ab\\256cd"));
    }

    @Test
    void ctor_toobig_escaped_end() {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(() -> new Name("ab\\256"));
    }

    @Test
    void ctor_idn_throws() {
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> new Name("\u95e8.example.org."));
    }

    @Test
    void ctor_max_label_escaped() throws TextParseException {
      // name with a 63 char label containing an escape
      Name n = new Name("aaaa\\100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.");
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(3);
      assertThat(n.length()).isEqualTo((short) 67);
      assertThat(n.getLabel(0))
          .containsExactly(
              new byte[] {
                63,
                'a',
                'a',
                'a',
                'a',
                (byte) 100,
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a'
              });
      assertThat(n.getLabel(1)).containsExactly(new byte[] {1, 'b'});
      assertThat(n.getLabelString(1)).isEqualTo("b");
      assertThat(n.getLabel(2)).containsExactly(new byte[] {0});
      assertThat(n.getLabelString(2)).isEmpty();
    }

    @Test
    void ctor_max_labels() throws TextParseException {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < 127; ++i) {
        sb.append("a.");
      }
      Name n = new Name(sb.toString());
      assertThat(n.isAbsolute()).isTrue();
      assertThat(n.isWild()).isFalse();
      assertThat(n.labels()).isEqualTo(128);
      assertThat(n.length()).isEqualTo((short) 255);
      for (int i = 0; i < 127; ++i) {
        assertThat(n.getLabel(i)).containsExactly(new byte[] {1, 'a'});
        assertThat(n.getLabelString(i)).isEqualTo("a");
      }
      assertThat(n.getLabel(127)).containsExactly(new byte[] {0});
      assertThat(n.getLabelString(127)).isEmpty();
    }

    @Test
    void ctor_toobig_label_escaped_end() {
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(
              () ->
                  new Name(
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\090.b."));
    }

    @Test
    void ctor_toobig_label_escaped() {
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(
              () ->
                  new Name(
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaa\\001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b."));
    }

    @Test
    void fromString() throws TextParseException {
      Name n = new Name(m_rel, m_abs_origin);
      Name n2 = Name.fromString(m_rel, m_abs_origin);
      assertThat(n2).isEqualTo(n);
    }

    @Test
    void fromString_at() throws TextParseException {
      Name n = Name.fromString("@", m_rel_origin);
      assertThat(n).isSameAs(m_rel_origin);
    }

    @Test
    void fromString_at_null() throws TextParseException {
      Name n = Name.fromString("@", null);
      assertThat(n).isSameAs(Name.empty);
    }

    @Test
    void fromString_dot() throws TextParseException {
      Name n = Name.fromString(".");
      assertThat(n).isSameAs(Name.root);
    }

    @Test
    void fromString_separators() throws TextParseException {
      assertThat(new Name(".")).isEqualTo(Name.root);
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> Name.fromString("\uFF0E"));
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> Name.fromString("\u3002"));
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> Name.fromString("\uFF61"));
    }

    @Test
    void fromConstantString() throws TextParseException {
      Name n = new Name(m_abs);
      Name n2 = Name.fromConstantString(m_abs);
      assertThat(n2).isEqualTo(n);
    }

    @Test
    void fromConstantString_invalid() {
      assertThatExceptionOfType(IllegalArgumentException.class)
          .isThrownBy(() -> Name.fromConstantString("junk..junk"));
    }
  }

  @Nested
  class Test_DNSInput_init {
    @Test
    void basic() throws IOException {

      final byte[] raw = {
        3, 'W', 'w', 'w', 7, 'D', 'n', 's', 'J', 'a', 'v', 'a', 3, 'o', 'r', 'g', 0
      };
      Name e = Name.fromString("Www.DnsJava.org.");

      Name n = new Name(raw);
      assertThat(n).isEqualTo(e);
    }

    @Test
    void incomplete() {
      assertThatExceptionOfType(WireParseException.class)
          .isThrownBy(() -> new Name(new byte[] {3, 'W', 'w', 'w'}));
    }

    @Test
    void root() throws WireParseException {
      final byte[] raw = {0};
      Name n = new Name(new DNSInput(raw));
      assertThat(n).isEqualTo(Name.root);
    }

    @Test
    void invalid_length() {
      assertThatExceptionOfType(WireParseException.class)
          .isThrownBy(() -> new Name(new byte[] {4, 'W', 'w', 'w'}));
    }

    @Test
    void max_label_length() throws TextParseException, WireParseException {
      byte[] raw = {
        63, 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 0
      };
      Name e = Name.fromString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.");

      Name n = new Name(new DNSInput(raw));
      assertThat(n).isEqualTo(e);
    }

    @Test
    void max_name() throws TextParseException, WireParseException {
      // absolute name with three 63-char labels and a 61-char label
      Name e =
          new Name(
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.");
      byte[] raw = {
        63, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
        'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
        'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
        'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 63, 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 63, 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
        'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
        'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
        'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 61, 'd', 'd', 'd', 'd', 'd',
        'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
        'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
        'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
        'd', 'd', 0
      };

      Name n = new Name(new DNSInput(raw));
      assertThat(n).isEqualTo(e);
    }

    @Test
    void toolong_name() {
      // absolute name with three 63-char labels and a 62-char label
      byte[] raw = {
        63, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
        'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
        'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
        'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 63, 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
        'b', 'b', 63, 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
        'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
        'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
        'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 62, 'd', 'd', 'd', 'd', 'd',
        'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
        'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
        'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
        'd', 'd', 'd', 0
      };

      assertThatExceptionOfType(WireParseException.class)
          .isThrownBy(() -> new Name(new DNSInput(raw)));
    }

    @Test
    void max_labels() throws TextParseException, WireParseException {
      byte[] raw = {
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 0
      };
      Name e =
          Name.fromString(
              "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.");
      Name n = new Name(new DNSInput(raw));
      assertThat(n.labels()).isEqualTo(128);
      assertThat(n).isEqualTo(e);
    }

    @Test
    void toomany_labels() {
      byte[] raw = {
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
        1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 0
      };
      assertThatExceptionOfType(WireParseException.class)
          .isThrownBy(() -> new Name(new DNSInput(raw)));
    }

    @Test
    void basic_compression() throws TextParseException, WireParseException {
      byte[] raw = {10, 3, 'a', 'b', 'c', 0, (byte) 0xC0, 1};
      Name e = Name.fromString("abc.");

      DNSInput in = new DNSInput(raw);
      in.jump(6);

      Name n = new Name(in);
      assertThat(n).isEqualTo(e);
    }

    @Test
    void two_pointer_compression() throws TextParseException, WireParseException {
      byte[] raw = {10, 3, 'a', 'b', 'c', 0, (byte) 0xC0, 1, (byte) 0xC0, 6};
      Name e = Name.fromString("abc.");

      DNSInput in = new DNSInput(raw);
      in.jump(8);

      Name n = new Name(in);
      assertThat(n).isEqualTo(e);
    }

    @Test
    void two_part_compression() throws TextParseException, WireParseException {
      byte[] raw = {10, 3, 'a', 'b', 'c', 0, 1, 'B', (byte) 0xC0, 1};
      Name e = Name.fromString("B.abc.");

      DNSInput in = new DNSInput(raw);
      in.jump(6);

      Name n = new Name(in);
      assertThat(n).isEqualTo(e);
    }

    @Test
    void long_jump_compression() throws TextParseException, WireParseException {
      // pointer to name beginning at index 256
      byte[] raw = {
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        12,
        3,
        'a',
        'b',
        'c',
        0,
        (byte) 0xC1,
        0
      };
      Name e = Name.fromString("abc.");

      DNSInput in = new DNSInput(raw);
      in.jump(261);
      Name n = new Name(in);
      assertThat(n).isEqualTo(e);
    }

    @Test
    void bad_compression() {
      byte[] raw = {(byte) 0xC0, 2, 0};
      assertThatExceptionOfType(WireParseException.class)
          .isThrownBy(() -> new Name(new DNSInput(raw)));
    }

    @Test
    void bad_label_reserved_type1() {
      byte[] raw = {(byte) 0b0100_0000, 2, 0};
      Exception e =
          assertThatExceptionOfType(WireParseException.class)
              .isThrownBy(() -> new Name(new DNSInput(raw)))
              .actual();
      assertThat(e.getMessage()).isEqualTo("bad label type");
    }

    @Test
    void bad_label_reserved_type2() {
      byte[] raw = {(byte) 0b1000_0000, 2, 0};
      Exception e =
          assertThatExceptionOfType(WireParseException.class)
              .isThrownBy(() -> new Name(new DNSInput(raw)))
              .actual();
      assertThat(e.getMessage()).isEqualTo("bad label type");
    }

    @Test
    void basic_compression_state_restore() throws TextParseException, WireParseException {
      byte[] raw = {10, 3, 'a', 'b', 'c', 0, (byte) 0xC0, 1, 3, 'd', 'e', 'f', 0};
      Name e = Name.fromString("abc.");
      Name e2 = Name.fromString("def.");

      DNSInput in = new DNSInput(raw);
      in.jump(6);

      Name n = new Name(in);
      assertThat(n).isEqualTo(e);

      n = new Name(in);
      assertThat(n).isEqualTo(e2);
    }

    @Test
    void two_part_compression_state_restore() throws TextParseException, WireParseException {
      byte[] raw = {10, 3, 'a', 'b', 'c', 0, 1, 'B', (byte) 0xC0, 1, 3, 'd', 'e', 'f', 0};
      Name e = Name.fromString("B.abc.");
      Name e2 = Name.fromString("def.");

      DNSInput in = new DNSInput(raw);
      in.jump(6);

      Name n = new Name(in);
      assertThat(n).isEqualTo(e);

      n = new Name(in);
      assertThat(n).isEqualTo(e2);
    }
  }

  @Test
  void init_from_name() throws TextParseException {
    Name n = new Name("A.B.c.d.");
    Name e = new Name("B.c.d.");
    Name o = new Name(n, 1);
    assertThat(o).isEqualTo(e);
  }

  @Test
  void init_from_name_root() throws TextParseException {
    Name n = new Name("A.B.c.d.");
    Name o = new Name(n, 4);
    assertThat(o).isEqualTo(Name.root);
  }

  @Test
  void init_from_name_empty() throws TextParseException {
    Name n = new Name("A.B.c.d.");
    Name n2 = new Name(n, 5);

    assertThat(n2.isAbsolute()).isFalse();
    assertThat(n2.isWild()).isFalse();
    assertThat(n2.labels()).isZero();
    assertThat(n2.length()).isZero();
  }

  @Test
  void init_from_name_labels_exceeded() throws TextParseException {
    Name n = new Name("a.b.c.d.");
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new Name(n, 6));
  }

  @Test
  void init_from_name_labels_offset() throws TextParseException {
    // 18 labels + root to exceed the cached offsets
    Name n = new Name("a.b.c.d.e.f.g.h.1.2.3.4.5.6.7.8.9.0.");
    assertThat(new Name(n, 8)).isEqualTo(Name.fromConstantString("1.2.3.4.5.6.7.8.9.0."));
  }

  @Test
  void concatenate_basic() throws NameTooLongException, TextParseException {
    Name p = Name.fromString("A.B");
    Name s = Name.fromString("c.d.");
    Name e = Name.fromString("A.B.c.d.");

    Name n = Name.concatenate(p, s);
    assertThat(n).isEqualTo(e);
  }

  @Test
  void concatenate_abs_prefix() throws NameTooLongException, TextParseException {
    Name p = Name.fromString("A.B.");
    Name s = Name.fromString("c.d.");
    Name e = Name.fromString("A.B.");

    Name n = Name.concatenate(p, s);
    assertThat(n).isEqualTo(e);
  }

  @Test
  void concatenate_too_long() throws TextParseException {
    Name p =
        Name.fromString(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    Name s =
        Name.fromString(
            "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.");

    assertThatExceptionOfType(NameTooLongException.class).isThrownBy(() -> Name.concatenate(p, s));
  }

  @Test
  void relativize() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name dom = Name.fromString("c.");
    Name exp = Name.fromString("a.b");

    Name n = sub.relativize(dom);
    assertThat(n).isEqualTo(exp);
  }

  @Test
  void relativize_null_origin() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name dom = null;

    Name n = sub.relativize(dom);
    assertThat(n).isEqualTo(sub);
  }

  @Test
  void relativize_disjoint() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name dom = Name.fromString("e.f.");

    Name n = sub.relativize(dom);
    assertThat(n).isEqualTo(sub);
  }

  @Test
  void relativize_root() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name dom = Name.fromString(".");
    Name exp = Name.fromString("a.b.c");

    Name n = sub.relativize(dom);
    assertThat(n).isEqualTo(exp);
  }

  @Test
  void wild() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name exp = Name.fromString("*.b.c.");

    Name n = sub.wild(1);
    assertThat(n).isEqualTo(exp);
  }

  @Test
  void wild_abs() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name exp = Name.fromString("*.");

    Name n = sub.wild(3);
    assertThat(n).isEqualTo(exp);
  }

  @Test
  void wild_toobig() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> sub.wild(4));
  }

  @Test
  void wild_toosmall() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> sub.wild(0));
  }

  @Test
  void fromDNAME() throws NameTooLongException, TextParseException {
    Name own = new Name("the.owner.");
    Name alias = new Name("the.alias.");
    DNAMERecord dnr = new DNAMERecord(own, DClass.IN, 0xABCD, alias);
    Name sub = new Name("sub.the.owner.");
    Name exp = new Name("sub.the.alias.");

    Name n = sub.fromDNAME(dnr);
    assertThat(n).isEqualTo(exp);
  }

  @Test
  void fromDNAME_toobig() throws TextParseException {
    Name own = new Name("the.owner.");
    Name alias =
        new Name(
            "the.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.");
    DNAMERecord dnr = new DNAMERecord(own, DClass.IN, 0xABCD, alias);
    Name sub =
        new Name("ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.the.owner.");

    assertThatExceptionOfType(NameTooLongException.class).isThrownBy(() -> sub.fromDNAME(dnr));
  }

  @Test
  void fromDNAME_disjoint() throws NameTooLongException, TextParseException {
    Name own = new Name("the.owner.");
    Name alias = new Name("the.alias.");
    DNAMERecord dnr = new DNAMERecord(own, DClass.IN, 0xABCD, alias);

    Name sub = new Name("sub.the.other");

    assertThat(sub.fromDNAME(dnr)).isNull();
  }

  @Test
  void label_min() throws TextParseException {
    Name n = new Name("a.b.c.");
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> n.getLabel(-1));
  }

  @Test
  void label_max() throws TextParseException {
    Name n = new Name("a.b.c.");
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> n.getLabel(5));
  }

  @Test
  void subdomain_abs() throws TextParseException {
    Name dom = new Name("the.domain.");
    Name sub = new Name("sub.of.the.domain.");
    assertThat(sub.subdomain(dom)).isTrue();
    assertThat(dom.subdomain(sub)).isFalse();
  }

  @Test
  void subdomain_rel() throws TextParseException {
    Name dom = new Name("the.domain");
    Name sub = new Name("sub.of.the.domain");
    assertThat(sub.subdomain(dom)).isTrue();
    assertThat(dom.subdomain(sub)).isFalse();
  }

  @Test
  void subdomain_equal() throws TextParseException {
    Name dom = new Name("the.domain");
    Name sub = new Name("the.domain");
    assertThat(sub.subdomain(dom)).isTrue();
    assertThat(dom.subdomain(sub)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        // absolute
        "This.Is.My.Absolute.Name.",
        // relative
        "This.Is.My.Relative.Name",
        // wildcard
        "*.A.b.c.e",
        // one escaped digit
        "my.escaped\\001.label.",
        // two escaped digits
        "my.escaped\\010.label.",
        // escaped junk
        "my.escaped.junk\\128.label.",
      })
  void variousToString(String in) throws TextParseException {
    Name n = new Name(in);
    assertThat(n).hasToString(in);
  }

  @Test
  void toString_at() throws TextParseException {
    Name n = new Name("@", null);
    assertThat(n).hasToString("@");
  }

  @Test
  void toString_root() {
    assertThat(Name.root).hasToString(".");
  }

  @Test
  void toString_special_char() throws WireParseException {
    byte[] raw = {1, '"', 1, '(', 1, ')', 1, '.', 1, ';', 1, '\\', 1, '@', 1, '$', 0};
    String exp = "\\\".\\(.\\).\\..\\;.\\\\.\\@.\\$.";
    Name n = new Name(new DNSInput(raw));
    assertThat(n).hasToString(exp);
  }

  @Nested
  class Test_toWire {
    @Test
    void rel() throws TextParseException {
      Name n = new Name("A.Relative.Name");
      DNSOutput out = new DNSOutput();
      assertThatExceptionOfType(IllegalArgumentException.class)
          .isThrownBy(() -> n.toWire(out, null));
    }

    @Test
    void null_Compression() throws TextParseException {
      byte[] raw = {1, 'A', 5, 'B', 'a', 's', 'i', 'c', 4, 'N', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      DNSOutput o = new DNSOutput();
      n.toWire(o, null);

      assertThat(o.toByteArray()).containsExactly(raw);
    }

    @Test
    void empty_Compression() throws TextParseException {
      byte[] raw = {1, 'A', 5, 'B', 'a', 's', 'i', 'c', 4, 'N', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      DNSOutput o = new DNSOutput();
      n.toWire(o, c);

      assertThat(o.toByteArray()).containsExactly(raw);
      assertThat(c.get(n)).isZero();
    }

    @Test
    void with_exact_Compression() throws TextParseException {
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      c.add(256, n);
      byte[] exp = {(byte) 0xC1, 0x0};

      DNSOutput o = new DNSOutput();
      n.toWire(o, c);
      assertThat(o.toByteArray()).containsExactly(exp);
      assertThat(c.get(n)).isEqualTo(256);
    }

    @Test
    void with_partial_Compression() throws TextParseException {
      Name d = new Name("Basic.Name.");
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      c.add(257, d);
      byte[] exp = {1, 'A', (byte) 0xC1, 0x1};

      DNSOutput o = new DNSOutput();
      n.toWire(o, c);
      assertThat(o.toByteArray()).containsExactly(exp);
      assertThat(c.get(d)).isEqualTo(257);
      assertThat(c.get(n)).isZero();
    }

    @Test
    void ctor_0arg_rel() throws TextParseException {
      Name n = new Name("A.Relative.Name");
      assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(n::toWire);
    }

    @Test
    void ctor_0arg() throws TextParseException {
      byte[] raw = {1, 'A', 5, 'B', 'a', 's', 'i', 'c', 4, 'N', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      byte[] out = n.toWire();

      assertThat(out).containsExactly(raw);
    }

    @Test
    void root() {
      byte[] out = Name.root.toWire();
      assertThat(out).containsExactly(new byte[] {0});
    }

    @Test
    void ctor_3arg() throws TextParseException {
      Name d = new Name("Basic.Name.");
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      c.add(257, d);
      byte[] exp = {1, 'A', (byte) 0xC1, 0x1};

      DNSOutput o = new DNSOutput();
      n.toWire(o, c, false);
      assertThat(o.toByteArray()).containsExactly(exp);
      assertThat(c.get(d)).isEqualTo(257);
      assertThat(c.get(n)).isZero();
    }
  }

  @Nested
  class Test_toWireCanonical {
    @Test
    void basic() throws TextParseException {
      byte[] raw = {1, 'a', 5, 'b', 'a', 's', 'i', 'c', 4, 'n', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      DNSOutput o = new DNSOutput();
      n.toWireCanonical(o);

      assertThat(o.toByteArray()).containsExactly(raw);
    }

    @Test
    void ctor_0arg() throws TextParseException {
      byte[] raw = {1, 'a', 5, 'b', 'a', 's', 'i', 'c', 4, 'n', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      byte[] out = n.toWireCanonical();

      assertThat(out).containsExactly(raw);
    }

    @Test
    void root() {
      byte[] out = Name.root.toWireCanonical();
      assertThat(out).containsExactly(new byte[] {0});
    }

    @Test
    void empty() throws TextParseException {
      Name n = new Name("@", null);
      byte[] out = n.toWireCanonical();
      assertThat(out).isEmpty();
    }

    @Test
    void ctor_3arg() throws TextParseException {
      Name d = new Name("Basic.Name.");
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      c.add(257, d);
      byte[] exp = {1, 'a', 5, 'b', 'a', 's', 'i', 'c', 4, 'n', 'a', 'm', 'e', 0};

      DNSOutput o = new DNSOutput();
      n.toWire(o, c, true);
      assertThat(o.toByteArray()).containsExactly(exp);
      assertThat(c.get(d)).isEqualTo(257);
      assertThat(c.get(n)).isEqualTo(-1);
    }
  }

  @Nested
  class Test_equals {
    @Test
    void same() throws TextParseException {
      Name n = new Name("A.Name.");
      assertThat(n).isEqualTo(n);
    }

    @Test
    void test_null() throws TextParseException {
      Name n = new Name("A.Name.");
      assertThat(n).isNotEqualTo(null);
    }

    @Test
    void notName() throws TextParseException {
      Name n = new Name("A.Name.");
      assertThat(new Object()).isNotEqualTo(n);
    }

    @Test
    void abs() throws TextParseException {
      Name n = new Name("A.Name.");
      Name n2 = new Name("a.name.");

      assertThat(n2).isEqualTo(n);
      assertThat(n).isEqualTo(n2);
    }

    @Test
    void rel() throws TextParseException {
      Name n1 = new Name("A.Relative.Name");
      Name n2 = new Name("a.relative.name");

      assertThat(n2).isEqualTo(n1);
      assertThat(n1).isEqualTo(n2);
    }

    @Test
    void mixed() throws TextParseException {
      Name n1 = new Name("A.Name");
      Name n2 = new Name("a.name.");

      assertThat(n2).isNotEqualTo(n1);
      assertThat(n1).isNotEqualTo(n2);
    }

    @Test
    void weird() throws TextParseException {
      Name n1 = new Name("ab.c");
      Name n2 = new Name("abc.");

      assertThat(n2).isNotEqualTo(n1);
      assertThat(n1).isNotEqualTo(n2);
    }
  }

  @Nested
  class Test_compareTo {
    @Test
    void equal() throws TextParseException {
      Name n1 = new Name("A.Name.");
      Name n2 = new Name("a.name.");

      assertThat(n1).isEqualByComparingTo(n2);
      assertThat(n2).isEqualByComparingTo(n1);
    }

    @Test
    void same() throws TextParseException {
      Name n = new Name("A.Name.");

      //noinspection EqualsWithItself
      assertThat(n).isEqualByComparingTo(n);
    }

    @Test
    void close() throws TextParseException {
      Name n1 = new Name("a.name");
      Name n2 = new Name("a.name.");

      assertThat(n1).isGreaterThan(n2);
      assertThat(n2).isLessThan(n1);
    }

    @ParameterizedTest
    @CsvSource({
      // disjoint
      "b, c",
      // label_prefix
      "thisIs.a., thisIsGreater.a.",
      // more_labels
      "c.b.a., d.c.b.a.",
      // octal_digits_low
      "\\004.b.a., c.b.a.",
      // octal_digits_high
      "c.b.a.,\\237.b.a.",
    })
    void compare(String name1, String name2) throws TextParseException {
      Name n1 = new Name(name1);
      Name n2 = new Name(name2);

      assertThat(n1).isLessThan(n2);
      assertThat(n2).isGreaterThan(n1);
    }
  }

  @Test
  void canonicalize() throws TextParseException {
    Name n1 = new Name("ABC.com");
    Name n2 = new Name("abc.com");
    Name n3 = new Name("\\193.com");

    Name cn1 = n1.canonicalize();
    Name cn2 = n2.canonicalize();
    Name cn3 = n3.canonicalize();

    assertNotSame(n1, cn1);
    assertThat(cn1).isEqualTo(n1);
    assertThat(cn2).isSameAs(n2);
    assertThat(cn3).isSameAs(n3);
    assertThat(cn2).hasToString(cn1.toString());
    assertThat(n2.toString()).isNotEqualTo(n1.toString());
    assertThat(cn2).hasToString(cn1.toString());
  }

  @Test
  void to_string() throws TextParseException {
    Name n1 = new Name("abc.com");
    Name n2 = new Name("abc.com.");

    assertThat(n1.toString(true)).isEqualTo(n1.toString(true));
    assertThat(n2.toString(false)).isNotEqualTo(n2.toString(true));
    assertThat(n2.toString(false)).isEqualTo(n2.toString(true) + ".");
    assertThat(Name.root.toString(false)).isEqualTo(Name.root.toString(true));
    assertThat(Name.empty.toString(false)).isEqualTo(Name.empty.toString(true));
  }

  @Test
  void absolute() throws TextParseException {
    Name n1 = new Name("abc.com");
    Name n2 = new Name("abc.com.");
    Name n3 = new Name("abc.com", Name.root);
    Name n4 = new Name("abc.com", n1);
    Name n5 = new Name("abc.com\\000");

    assertThat(n1.isAbsolute()).isFalse();
    assertThat(n2.isAbsolute()).isTrue();
    assertThat(n3.isAbsolute()).isTrue();
    assertThat(n4.isAbsolute()).isFalse();
    assertThat(n5.isAbsolute()).isFalse();
  }
}
