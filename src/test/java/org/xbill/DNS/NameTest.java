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

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class NameTest {
  static class Test_String_init {
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
      assertThrows(TextParseException.class, () -> new Name(""));
    }

    @Test
    void ctor_at_null_origin() throws TextParseException {
      Name n = new Name("@");
      assertFalse(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(0, n.labels());
      assertEquals(0, n.length());
    }

    @Test
    void ctor_at_abs_origin() throws TextParseException {
      Name n = new Name("@", m_abs_origin);
      assertEquals(m_abs_origin, n);
    }

    @Test
    void ctor_at_rel_origin() throws TextParseException {
      Name n = new Name("@", m_rel_origin);
      assertEquals(m_rel_origin, n);
    }

    @Test
    void ctor_dot() throws TextParseException {
      Name n = new Name(".");
      assertEquals(Name.root, n);
      assertNotSame(Name.root, n);
      assertEquals(1, n.labels());
      assertEquals(1, n.length());
    }

    @Test
    void ctor_wildcard() throws TextParseException {
      Name n = new Name("*");
      assertFalse(n.isAbsolute());
      assertTrue(n.isWild());
      assertEquals(1, n.labels());
      assertEquals(2, n.length());
      assertArrayEquals(new byte[] {1, '*'}, n.getLabel(0));
      assertEquals("*", n.getLabelString(0));
    }

    @Test
    void ctor_abs() throws TextParseException {
      Name n = new Name(m_abs);
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(4, n.labels());
      assertEquals(17, n.length());
      assertArrayEquals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0));
      assertEquals("WWW", n.getLabelString(0));
      assertArrayEquals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1));
      assertEquals("DnsJava", n.getLabelString(1));
      assertArrayEquals(new byte[] {3, 'o', 'r', 'g'}, n.getLabel(2));
      assertEquals("org", n.getLabelString(2));
      assertArrayEquals(new byte[] {0}, n.getLabel(3));
      assertEquals("", n.getLabelString(3));
    }

    @Test
    void ctor_rel() throws TextParseException {
      Name n = new Name(m_rel);
      assertFalse(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(2, n.labels());
      assertEquals(12, n.length());
      assertArrayEquals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0));
      assertEquals("WWW", n.getLabelString(0));
      assertArrayEquals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1));
      assertEquals("DnsJava", n.getLabelString(1));
    }

    @Test
    void ctor_7label() throws TextParseException {
      // 7 is the number of label positions that are cached
      Name n = new Name("a.b.c.d.e.f.");
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(7, n.labels());
      assertEquals(13, n.length());
      assertArrayEquals(new byte[] {1, 'a'}, n.getLabel(0));
      assertEquals("a", n.getLabelString(0));
      assertArrayEquals(new byte[] {1, 'b'}, n.getLabel(1));
      assertEquals("b", n.getLabelString(1));
      assertArrayEquals(new byte[] {1, 'c'}, n.getLabel(2));
      assertEquals("c", n.getLabelString(2));
      assertArrayEquals(new byte[] {1, 'd'}, n.getLabel(3));
      assertEquals("d", n.getLabelString(3));
      assertArrayEquals(new byte[] {1, 'e'}, n.getLabel(4));
      assertEquals("e", n.getLabelString(4));
      assertArrayEquals(new byte[] {1, 'f'}, n.getLabel(5));
      assertEquals("f", n.getLabelString(5));
      assertArrayEquals(new byte[] {0}, n.getLabel(6));
      assertEquals("", n.getLabelString(6));
    }

    @Test
    void ctor_8label() throws TextParseException {
      // 7 is the number of label positions that are cached
      Name n = new Name("a.b.c.d.e.f.g.");
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(8, n.labels());
      assertEquals(15, n.length());
      assertArrayEquals(new byte[] {1, 'a'}, n.getLabel(0));
      assertEquals("a", n.getLabelString(0));
      assertArrayEquals(new byte[] {1, 'b'}, n.getLabel(1));
      assertEquals("b", n.getLabelString(1));
      assertArrayEquals(new byte[] {1, 'c'}, n.getLabel(2));
      assertEquals("c", n.getLabelString(2));
      assertArrayEquals(new byte[] {1, 'd'}, n.getLabel(3));
      assertEquals("d", n.getLabelString(3));
      assertArrayEquals(new byte[] {1, 'e'}, n.getLabel(4));
      assertEquals("e", n.getLabelString(4));
      assertArrayEquals(new byte[] {1, 'f'}, n.getLabel(5));
      assertEquals("f", n.getLabelString(5));
      assertArrayEquals(new byte[] {1, 'g'}, n.getLabel(6));
      assertEquals("g", n.getLabelString(6));
      assertArrayEquals(new byte[] {0}, n.getLabel(7));
      assertEquals("", n.getLabelString(7));
    }

    @Test
    void ctor_removed_label() throws TextParseException, NameTooLongException {
      String pre = "prepend";
      Name stripped = new Name(Name.fromString("sub.domain.example."), 1);
      Name concat = new Name(pre, stripped);
      assertEquals(Name.concatenate(Name.fromString(pre), stripped), concat);
      assertEquals(Name.fromString(pre, stripped), concat);
      assertEquals("prepend.domain.example.", concat.toString());
    }

    @Test
    void ctor_abs_abs_origin() throws TextParseException {
      Name n = new Name(m_abs, m_abs_origin);
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(4, n.labels());
      assertEquals(17, n.length());
      assertArrayEquals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0));
      assertEquals("WWW", n.getLabelString(0));
      assertArrayEquals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1));
      assertEquals("DnsJava", n.getLabelString(1));
      assertArrayEquals(new byte[] {3, 'o', 'r', 'g'}, n.getLabel(2));
      assertEquals("org", n.getLabelString(2));
      assertArrayEquals(new byte[] {0}, n.getLabel(3));
      assertEquals("", n.getLabelString(3));
    }

    @Test
    void ctor_abs_rel_origin() throws TextParseException {
      Name n = new Name(m_abs, m_rel_origin);
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(4, n.labels());
      assertEquals(17, n.length());
      assertArrayEquals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0));
      assertEquals("WWW", n.getLabelString(0));
      assertArrayEquals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1));
      assertEquals("DnsJava", n.getLabelString(1));
      assertArrayEquals(new byte[] {3, 'o', 'r', 'g'}, n.getLabel(2));
      assertEquals("org", n.getLabelString(2));
      assertArrayEquals(new byte[] {0}, n.getLabel(3));
      assertEquals("", n.getLabelString(3));
    }

    @Test
    void ctor_rel_abs_origin() throws TextParseException {
      Name n = new Name(m_rel, m_abs_origin);
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(4, n.labels());
      assertEquals(18, n.length());
      assertArrayEquals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0));
      assertEquals("WWW", n.getLabelString(0));
      assertArrayEquals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1));
      assertEquals("DnsJava", n.getLabelString(1));
      assertArrayEquals(new byte[] {4, 'O', 'r', 'i', 'g'}, n.getLabel(2));
      assertEquals("Orig", n.getLabelString(2));
      assertArrayEquals(new byte[] {0}, n.getLabel(3));
      assertEquals("", n.getLabelString(3));
    }

    @Test
    void ctor_invalid_label() {
      assertThrows(TextParseException.class, () -> new Name("junk..junk."));
    }

    @Test
    void ctor_max_label() throws TextParseException {
      // name with a 63 char label
      Name n = new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.");
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(3, n.labels());
      assertEquals(67, n.length());
      assertArrayEquals(
          new byte[] {
            63, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'
          },
          n.getLabel(0));
      assertEquals(
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", n.getLabelString(0));
      assertArrayEquals(new byte[] {1, 'b'}, n.getLabel(1));
      assertEquals("b", n.getLabelString(1));
      assertArrayEquals(new byte[] {0}, n.getLabel(2));
      assertEquals("", n.getLabelString(2));
    }

    @Test
    void ctor_toobig_label() {
      // name with a 64 char label
      assertThrows(
          TextParseException.class,
          () -> new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b."));
    }

    @Test
    void ctor_length_too_long_rel() {
      // We want to fail to crate this as there is no way to make a Name that long absolute,
      // which means that it can not be used for lookups or updates.
      String label63 = IntStream.range(0, 63).mapToObj(i -> "a").collect(Collectors.joining());
      String label62 = IntStream.range(0, 62).mapToObj(i -> "a").collect(Collectors.joining());
      assertThrows(
          TextParseException.class,
          () -> new Name(format("%s.%s.%s.%s", label63, label63, label63, label62)));
    }

    @Test
    void ctor_longest_allowed_rel() throws TextParseException {
      // relative name with three 63-char labels and a 61-char label
      Name n =
          new Name(
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
      assertFalse(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(4, n.labels());
      assertEquals(254, n.length());
    }

    @Test
    void ctor_max_length_abs() throws TextParseException {
      // absolute name with three 63-char labels and a 61-char label
      Name n =
          new Name(
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.");
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(5, n.labels());
      assertEquals(255, n.length());
    }

    @Test
    void ctor_escaped() throws TextParseException {
      Name n = new Name("ab\\123cd");
      assertFalse(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(1, n.labels());
      assertEquals(6, n.length());
      assertArrayEquals(new byte[] {5, 'a', 'b', (byte) 123, 'c', 'd'}, n.getLabel(0));
    }

    @Test
    void ctor_escaped_end() throws TextParseException {
      Name n = new Name("abcd\\123");
      assertFalse(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(1, n.labels());
      assertEquals(6, n.length());
      assertArrayEquals(new byte[] {5, 'a', 'b', 'c', 'd', (byte) 123}, n.getLabel(0));
    }

    @Test
    void ctor_short_escaped() {
      assertThrows(TextParseException.class, () -> new Name("ab\\12cd"));
    }

    @Test
    void ctor_short_escaped_end() {
      assertThrows(TextParseException.class, () -> new Name("ab\\12"));
    }

    @Test
    void ctor_empty_escaped_end() {
      assertThrows(TextParseException.class, () -> new Name("ab\\"));
    }

    @Test
    void ctor_toobig_escaped() {
      assertThrows(TextParseException.class, () -> new Name("ab\\256cd"));
    }

    @Test
    void ctor_toobig_escaped_end() {
      assertThrows(TextParseException.class, () -> new Name("ab\\256"));
    }

    @Test
    void ctor_max_label_escaped() throws TextParseException {
      // name with a 63 char label containing an escape
      Name n = new Name("aaaa\\100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.");
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(3, n.labels());
      assertEquals(67, n.length());
      assertArrayEquals(
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
          },
          n.getLabel(0));
      assertArrayEquals(new byte[] {1, 'b'}, n.getLabel(1));
      assertEquals("b", n.getLabelString(1));
      assertArrayEquals(new byte[] {0}, n.getLabel(2));
      assertEquals("", n.getLabelString(2));
    }

    @Test
    void ctor_max_labels() throws TextParseException {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < 127; ++i) {
        sb.append("a.");
      }
      Name n = new Name(sb.toString());
      assertTrue(n.isAbsolute());
      assertFalse(n.isWild());
      assertEquals(128, n.labels());
      assertEquals(255, n.length());
      for (int i = 0; i < 127; ++i) {
        assertArrayEquals(new byte[] {1, 'a'}, n.getLabel(i));
        assertEquals("a", n.getLabelString(i));
      }
      assertArrayEquals(new byte[] {0}, n.getLabel(127));
      assertEquals("", n.getLabelString(127));
    }

    @Test
    void ctor_toobig_label_escaped_end() {
      assertThrows(
          TextParseException.class,
          () ->
              new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\090.b."));
    }

    @Test
    void ctor_toobig_label_escaped() {
      assertThrows(
          TextParseException.class,
          () ->
              new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaa\\001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b."));
    }

    @Test
    void fromString() throws TextParseException {
      Name n = new Name(m_rel, m_abs_origin);
      Name n2 = Name.fromString(m_rel, m_abs_origin);
      assertEquals(n, n2);
    }

    @Test
    void fromString_at() throws TextParseException {
      Name n = Name.fromString("@", m_rel_origin);
      assertSame(m_rel_origin, n);
    }

    @Test
    void fromString_dot() throws TextParseException {
      Name n = Name.fromString(".");
      assertSame(Name.root, n);
    }

    @Test
    void fromConstantString() throws TextParseException {
      Name n = new Name(m_abs);
      Name n2 = Name.fromConstantString(m_abs);
      assertEquals(n, n2);
    }

    @Test
    void fromConstantString_invalid() {
      assertThrows(IllegalArgumentException.class, () -> Name.fromConstantString("junk..junk"));
    }
  }

  static class Test_DNSInput_init {
    @Test
    void basic() throws IOException {

      final byte[] raw =
          new byte[] {3, 'W', 'w', 'w', 7, 'D', 'n', 's', 'J', 'a', 'v', 'a', 3, 'o', 'r', 'g', 0};
      Name e = Name.fromString("Www.DnsJava.org.");

      Name n = new Name(raw);
      assertEquals(e, n);
    }

    @Test
    void incomplete() {
      assertThrows(WireParseException.class, () -> new Name(new byte[] {3, 'W', 'w', 'w'}));
    }

    @Test
    void root() throws WireParseException {
      final byte[] raw = new byte[] {0};
      Name n = new Name(new DNSInput(raw));
      assertEquals(Name.root, n);
    }

    @Test
    void invalid_length() {
      assertThrows(WireParseException.class, () -> new Name(new byte[] {4, 'W', 'w', 'w'}));
    }

    @Test
    void max_label_length() throws TextParseException, WireParseException {
      byte[] raw =
          new byte[] {
            63, 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 0
          };
      Name e = Name.fromString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.");

      Name n = new Name(new DNSInput(raw));
      assertEquals(e, n);
    }

    @Test
    void max_name() throws TextParseException, WireParseException {
      // absolute name with three 63-char labels and a 61-char label
      Name e =
          new Name(
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.");
      byte[] raw =
          new byte[] {
            63, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 63, 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 63, 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
            'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
            'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
            'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
            'c', 'c', 61, 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
            'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
            'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
            'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 0
          };

      Name n = new Name(new DNSInput(raw));
      assertEquals(e, n);
    }

    @Test
    void toolong_name() {
      // absolute name with three 63-char labels and a 62-char label
      byte[] raw =
          new byte[] {
            63, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
            'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 63, 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
            'b', 'b', 'b', 'b', 'b', 'b', 'b', 63, 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
            'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
            'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
            'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
            'c', 'c', 62, 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
            'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
            'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
            'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 0
          };

      assertThrows(WireParseException.class, () -> new Name(new DNSInput(raw)));
    }

    @Test
    void max_labels() throws TextParseException, WireParseException {
      byte[] raw =
          new byte[] {
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
      assertEquals(128, n.labels());
      assertEquals(e, n);
    }

    @Test
    void toomany_labels() {
      byte[] raw =
          new byte[] {
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
      assertThrows(WireParseException.class, () -> new Name(new DNSInput(raw)));
    }

    @Test
    void basic_compression() throws TextParseException, WireParseException {
      byte[] raw = new byte[] {10, 3, 'a', 'b', 'c', 0, (byte) 0xC0, 1};
      Name e = Name.fromString("abc.");

      DNSInput in = new DNSInput(raw);
      in.jump(6);

      Name n = new Name(in);
      assertEquals(e, n);
    }

    @Test
    void two_pointer_compression() throws TextParseException, WireParseException {
      byte[] raw = new byte[] {10, 3, 'a', 'b', 'c', 0, (byte) 0xC0, 1, (byte) 0xC0, 6};
      Name e = Name.fromString("abc.");

      DNSInput in = new DNSInput(raw);
      in.jump(8);

      Name n = new Name(in);
      assertEquals(e, n);
    }

    @Test
    void two_part_compression() throws TextParseException, WireParseException {
      byte[] raw = new byte[] {10, 3, 'a', 'b', 'c', 0, 1, 'B', (byte) 0xC0, 1};
      Name e = Name.fromString("B.abc.");

      DNSInput in = new DNSInput(raw);
      in.jump(6);

      Name n = new Name(in);
      assertEquals(e, n);
    }

    @Test
    void long_jump_compression() throws TextParseException, WireParseException {
      // pointer to name beginning at index 256
      byte[] raw =
          new byte[] {
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
      assertEquals(e, n);
    }

    @Test
    void bad_compression() {
      byte[] raw = new byte[] {(byte) 0xC0, 2, 0};
      assertThrows(WireParseException.class, () -> new Name(new DNSInput(raw)));
    }

    @Test
    void basic_compression_state_restore() throws TextParseException, WireParseException {
      byte[] raw = new byte[] {10, 3, 'a', 'b', 'c', 0, (byte) 0xC0, 1, 3, 'd', 'e', 'f', 0};
      Name e = Name.fromString("abc.");
      Name e2 = Name.fromString("def.");

      DNSInput in = new DNSInput(raw);
      in.jump(6);

      Name n = new Name(in);
      assertEquals(e, n);

      n = new Name(in);
      assertEquals(e2, n);
    }

    @Test
    void two_part_compression_state_restore() throws TextParseException, WireParseException {
      byte[] raw =
          new byte[] {10, 3, 'a', 'b', 'c', 0, 1, 'B', (byte) 0xC0, 1, 3, 'd', 'e', 'f', 0};
      Name e = Name.fromString("B.abc.");
      Name e2 = Name.fromString("def.");

      DNSInput in = new DNSInput(raw);
      in.jump(6);

      Name n = new Name(in);
      assertEquals(e, n);

      n = new Name(in);
      assertEquals(e2, n);
    }
  }

  @Test
  void init_from_name() throws TextParseException {
    Name n = new Name("A.B.c.d.");
    Name e = new Name("B.c.d.");
    Name o = new Name(n, 1);
    assertEquals(e, o);
  }

  @Test
  void init_from_name_root() throws TextParseException {
    Name n = new Name("A.B.c.d.");
    Name o = new Name(n, 4);
    assertEquals(Name.root, o);
  }

  @Test
  void init_from_name_empty() throws TextParseException {
    Name n = new Name("A.B.c.d.");
    Name n2 = new Name(n, 5);

    assertFalse(n2.isAbsolute());
    assertFalse(n2.isWild());
    assertEquals(0, n2.labels());
    assertEquals(0, n2.length());
  }

  @Test
  void concatenate_basic() throws NameTooLongException, TextParseException {
    Name p = Name.fromString("A.B");
    Name s = Name.fromString("c.d.");
    Name e = Name.fromString("A.B.c.d.");

    Name n = Name.concatenate(p, s);
    assertEquals(e, n);
  }

  @Test
  void concatenate_abs_prefix() throws NameTooLongException, TextParseException {
    Name p = Name.fromString("A.B.");
    Name s = Name.fromString("c.d.");
    Name e = Name.fromString("A.B.");

    Name n = Name.concatenate(p, s);
    assertEquals(e, n);
  }

  @Test
  void concatenate_too_long() throws TextParseException {
    Name p =
        Name.fromString(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    Name s =
        Name.fromString(
            "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.");

    assertThrows(NameTooLongException.class, () -> Name.concatenate(p, s));
  }

  @Test
  void relativize() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name dom = Name.fromString("c.");
    Name exp = Name.fromString("a.b");

    Name n = sub.relativize(dom);
    assertEquals(exp, n);
  }

  @Test
  void relativize_null_origin() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name dom = null;

    Name n = sub.relativize(dom);
    assertEquals(sub, n);
  }

  @Test
  void relativize_disjoint() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name dom = Name.fromString("e.f.");

    Name n = sub.relativize(dom);
    assertEquals(sub, n);
  }

  @Test
  void relativize_root() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name dom = Name.fromString(".");
    Name exp = Name.fromString("a.b.c");

    Name n = sub.relativize(dom);
    assertEquals(exp, n);
  }

  @Test
  void wild() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name exp = Name.fromString("*.b.c.");

    Name n = sub.wild(1);
    assertEquals(exp, n);
  }

  @Test
  void wild_abs() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    Name exp = Name.fromString("*.");

    Name n = sub.wild(3);
    assertEquals(exp, n);
  }

  @Test
  void wild_toobig() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    assertThrows(IllegalArgumentException.class, () -> sub.wild(4));
  }

  @Test
  void wild_toosmall() throws TextParseException {
    Name sub = Name.fromString("a.b.c.");
    assertThrows(IllegalArgumentException.class, () -> sub.wild(0));
  }

  @Test
  void fromDNAME() throws NameTooLongException, TextParseException {
    Name own = new Name("the.owner.");
    Name alias = new Name("the.alias.");
    DNAMERecord dnr = new DNAMERecord(own, DClass.IN, 0xABCD, alias);
    Name sub = new Name("sub.the.owner.");
    Name exp = new Name("sub.the.alias.");

    Name n = sub.fromDNAME(dnr);
    assertEquals(exp, n);
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

    assertThrows(NameTooLongException.class, () -> sub.fromDNAME(dnr));
  }

  @Test
  void fromDNAME_disjoint() throws NameTooLongException, TextParseException {
    Name own = new Name("the.owner.");
    Name alias = new Name("the.alias.");
    DNAMERecord dnr = new DNAMERecord(own, DClass.IN, 0xABCD, alias);

    Name sub = new Name("sub.the.other");

    assertNull(sub.fromDNAME(dnr));
  }

  @Test
  void subdomain_abs() throws TextParseException {
    Name dom = new Name("the.domain.");
    Name sub = new Name("sub.of.the.domain.");
    assertTrue(sub.subdomain(dom));
    assertFalse(dom.subdomain(sub));
  }

  @Test
  void subdomain_rel() throws TextParseException {
    Name dom = new Name("the.domain");
    Name sub = new Name("sub.of.the.domain");
    assertTrue(sub.subdomain(dom));
    assertFalse(dom.subdomain(sub));
  }

  @Test
  void subdomain_equal() throws TextParseException {
    Name dom = new Name("the.domain");
    Name sub = new Name("the.domain");
    assertTrue(sub.subdomain(dom));
    assertTrue(dom.subdomain(sub));
  }

  @Test
  void toString_abs() throws TextParseException {
    String in = "This.Is.My.Absolute.Name.";
    Name n = new Name(in);

    assertEquals(in, n.toString());
  }

  @Test
  void toString_rel() throws TextParseException {
    String in = "This.Is.My.Relative.Name";
    Name n = new Name(in);

    assertEquals(in, n.toString());
  }

  @Test
  void toString_at() throws TextParseException {
    Name n = new Name("@", null);
    assertEquals("@", n.toString());
  }

  @Test
  void toString_root() {
    assertEquals(".", Name.root.toString());
  }

  @Test
  void toString_wild() throws TextParseException {
    String in = "*.A.b.c.e";
    Name n = new Name(in);
    assertEquals(in, n.toString());
  }

  @Test
  void toString_escaped() throws TextParseException {
    String in = "my.escaped.junk\\128.label.";
    Name n = new Name(in);
    assertEquals(in, n.toString());
  }

  @Test
  void toString_special_char() throws WireParseException {
    byte[] raw = new byte[] {1, '"', 1, '(', 1, ')', 1, '.', 1, ';', 1, '\\', 1, '@', 1, '$', 0};
    String exp = "\\\".\\(.\\).\\..\\;.\\\\.\\@.\\$.";
    Name n = new Name(new DNSInput(raw));
    assertEquals(exp, n.toString());
  }

  @Test
  void toString_idn() throws TextParseException {
    String in = "café.éxemple.org";
    Name n = Name.fromString(in);
    assertEquals(in, n.toUnicodeString());
    assertEquals("xn--caf-dma.xn--xemple-9ua.org", n.toString());
  }

  static class Test_toWire {
    @Test
    void rel() throws TextParseException {
      Name n = new Name("A.Relative.Name");
      assertThrows(IllegalArgumentException.class, () -> n.toWire(new DNSOutput(), null));
    }

    @Test
    void null_Compression() throws TextParseException {
      byte[] raw = new byte[] {1, 'A', 5, 'B', 'a', 's', 'i', 'c', 4, 'N', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      DNSOutput o = new DNSOutput();
      n.toWire(o, null);

      assertArrayEquals(raw, o.toByteArray());
    }

    @Test
    void empty_Compression() throws TextParseException {
      byte[] raw = new byte[] {1, 'A', 5, 'B', 'a', 's', 'i', 'c', 4, 'N', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      DNSOutput o = new DNSOutput();
      n.toWire(o, c);

      assertArrayEquals(raw, o.toByteArray());
      assertEquals(0, c.get(n));
    }

    @Test
    void with_exact_Compression() throws TextParseException {
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      c.add(256, n);
      byte[] exp = new byte[] {(byte) 0xC1, 0x0};

      DNSOutput o = new DNSOutput();
      n.toWire(o, c);
      assertArrayEquals(exp, o.toByteArray());
      assertEquals(256, c.get(n));
    }

    @Test
    void with_partial_Compression() throws TextParseException {
      Name d = new Name("Basic.Name.");
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      c.add(257, d);
      byte[] exp = new byte[] {1, 'A', (byte) 0xC1, 0x1};

      DNSOutput o = new DNSOutput();
      n.toWire(o, c);
      assertArrayEquals(exp, o.toByteArray());
      assertEquals(257, c.get(d));
      assertEquals(0, c.get(n));
    }

    @Test
    void ctor_0arg_rel() throws TextParseException {
      Name n = new Name("A.Relative.Name");
      assertThrows(IllegalArgumentException.class, () -> n.toWire());
    }

    @Test
    void ctor_0arg() throws TextParseException {
      byte[] raw = new byte[] {1, 'A', 5, 'B', 'a', 's', 'i', 'c', 4, 'N', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      byte[] out = n.toWire();

      assertArrayEquals(raw, out);
    }

    @Test
    void root() {
      byte[] out = Name.root.toWire();
      assertArrayEquals(new byte[] {0}, out);
    }

    @Test
    void ctor_3arg() throws TextParseException {
      Name d = new Name("Basic.Name.");
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      c.add(257, d);
      byte[] exp = new byte[] {1, 'A', (byte) 0xC1, 0x1};

      DNSOutput o = new DNSOutput();
      n.toWire(o, c, false);
      assertArrayEquals(exp, o.toByteArray());
      assertEquals(257, c.get(d));
      assertEquals(0, c.get(n));
    }
  }

  static class Test_toWireCanonical {
    @Test
    void basic() throws TextParseException {
      byte[] raw = new byte[] {1, 'a', 5, 'b', 'a', 's', 'i', 'c', 4, 'n', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      DNSOutput o = new DNSOutput();
      n.toWireCanonical(o);

      assertArrayEquals(raw, o.toByteArray());
    }

    @Test
    void ctor_0arg() throws TextParseException {
      byte[] raw = new byte[] {1, 'a', 5, 'b', 'a', 's', 'i', 'c', 4, 'n', 'a', 'm', 'e', 0};
      Name n = new Name("A.Basic.Name.");

      byte[] out = n.toWireCanonical();

      assertArrayEquals(raw, out);
    }

    @Test
    void root() {
      byte[] out = Name.root.toWireCanonical();
      assertArrayEquals(new byte[] {0}, out);
    }

    @Test
    void empty() throws TextParseException {
      Name n = new Name("@", null);
      byte[] out = n.toWireCanonical();
      assertArrayEquals(new byte[0], out);
    }

    @Test
    void ctor_3arg() throws TextParseException {
      Name d = new Name("Basic.Name.");
      Name n = new Name("A.Basic.Name.");

      Compression c = new Compression();
      c.add(257, d);
      byte[] exp = new byte[] {1, 'a', 5, 'b', 'a', 's', 'i', 'c', 4, 'n', 'a', 'm', 'e', 0};

      DNSOutput o = new DNSOutput();
      n.toWire(o, c, true);
      assertArrayEquals(exp, o.toByteArray());
      assertEquals(257, c.get(d));
      assertEquals(-1, c.get(n));
    }
  }

  static class Test_equals {
    @Test
    void same() throws TextParseException {
      Name n = new Name("A.Name.");
      assertEquals(n, n);
    }

    @Test
    void test_null() throws TextParseException {
      Name n = new Name("A.Name.");
      assertNotEquals(null, n);
    }

    @Test
    void notName() throws TextParseException {
      Name n = new Name("A.Name.");
      assertNotEquals(n, new Object());
    }

    @Test
    void abs() throws TextParseException {
      Name n = new Name("A.Name.");
      Name n2 = new Name("a.name.");

      assertEquals(n, n2);
      assertEquals(n2, n);
    }

    @Test
    void rel() throws TextParseException {
      Name n1 = new Name("A.Relative.Name");
      Name n2 = new Name("a.relative.name");

      assertEquals(n1, n2);
      assertEquals(n2, n1);
    }

    @Test
    void mixed() throws TextParseException {
      Name n1 = new Name("A.Name");
      Name n2 = new Name("a.name.");

      assertNotEquals(n1, n2);
      assertNotEquals(n2, n1);
    }

    @Test
    void weird() throws TextParseException {
      Name n1 = new Name("ab.c");
      Name n2 = new Name("abc.");

      assertNotEquals(n1, n2);
      assertNotEquals(n2, n1);
    }

    @Test
    void idn() throws TextParseException {
      Name n1 = new Name("xn--caf-dma.xn--xemple-9ua.org.");
      Name n2 = new Name("café.éxemple.org.");

      assertEquals(n1, n2);
      assertEquals(n2, n1);
    }
  }

  static class Test_compareTo {
    @Test
    void equal() throws TextParseException {
      Name n1 = new Name("A.Name.");
      Name n2 = new Name("a.name.");

      assertEquals(0, n1.compareTo(n2));
      assertEquals(0, n2.compareTo(n1));
    }

    @Test
    void close() throws TextParseException {
      Name n1 = new Name("a.name");
      Name n2 = new Name("a.name.");

      assertTrue(n1.compareTo(n2) > 0);
      assertTrue(n2.compareTo(n1) < 0);
    }

    @Test
    void disjoint() throws TextParseException {
      Name n1 = new Name("b");
      Name n2 = new Name("c");

      assertTrue(n1.compareTo(n2) < 0);
      assertTrue(n2.compareTo(n1) > 0);
    }

    @Test
    void label_prefix() throws TextParseException {
      Name n1 = new Name("thisIs.a.");
      Name n2 = new Name("thisIsGreater.a.");

      assertTrue(n1.compareTo(n2) < 0);
      assertTrue(n2.compareTo(n1) > 0);
    }

    @Test
    void more_labels() throws TextParseException {
      Name n1 = new Name("c.b.a.");
      Name n2 = new Name("d.c.b.a.");

      assertTrue(n1.compareTo(n2) < 0);
      assertTrue(n2.compareTo(n1) > 0);
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
    assertEquals(n1, cn1);
    assertSame(n2, cn2);
    assertSame(n3, cn3);
    assertEquals(cn1.toString(), cn2.toString());
    assertNotEquals(n1.toString(), n2.toString());
    assertEquals(cn1.toString(), cn2.toString());
  }

  @Test
  void to_string() throws TextParseException {
    Name n1 = new Name("abc.com");
    Name n2 = new Name("abc.com.");

    assertEquals(n1.toString(true), n1.toString(true));
    assertNotEquals(n2.toString(true), n2.toString(false));
    assertEquals(n2.toString(true) + ".", n2.toString(false));
    assertEquals(Name.root.toString(true), Name.root.toString(false));
    assertEquals(Name.empty.toString(true), Name.empty.toString(false));
  }

  @Test
  void absolute() throws TextParseException {
    Name n1 = new Name("abc.com");
    Name n2 = new Name("abc.com.");
    Name n3 = new Name("abc.com", Name.root);
    Name n4 = new Name("abc.com", n1);
    Name n5 = new Name("abc.com\\000");

    assertFalse(n1.isAbsolute());
    assertTrue(n2.isAbsolute());
    assertTrue(n3.isAbsolute());
    assertFalse(n4.isAbsolute());
    assertFalse(n5.isAbsolute());
  }
}
