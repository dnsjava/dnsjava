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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

abstract class DNSInputTest {
  protected byte[] m_raw;
  protected DNSInput m_di;

  static class DNSInputArrayTest extends DNSInputTest {
    @BeforeEach
    void setUp() {
      m_raw = new byte[] {0, 1, 2, 3, 4, 5, (byte) 255, (byte) 255, (byte) 255, (byte) 255};
      m_di = new DNSInput(m_raw);
    }
  }

  static class DNSInputByteBufferTest extends DNSInputTest {
    @BeforeEach
    void setUp() {
      m_raw = new byte[] {0, 1, 2, 3, 4, 5, (byte) 255, (byte) 255, (byte) 255, (byte) 255};
      ByteBuffer buffer = ByteBuffer.allocate(m_raw.length + 2);
      buffer.putShort((short) 0xFF);
      buffer.put(m_raw);
      buffer.flip();
      buffer.getShort();
      m_di = new DNSInput(buffer);
    }
  }

  static class DNSInputByteBufferLimitTest extends DNSInputTest {
    @BeforeEach
    void setUp() {
      m_raw = new byte[] {0, 1, 2, 3, 4, 5, (byte) 255, (byte) 255, (byte) 255, (byte) 255};
      ByteBuffer buffer = ByteBuffer.allocate(m_raw.length + 10);
      buffer.putShort((short) 0xFF);
      buffer.put(m_raw);
      buffer.flip();
      buffer.getShort();
      buffer.limit(m_raw.length + 2);
      m_di = new DNSInput(buffer);
    }
  }

  static class DNSInputByteBufferLimitOffsetTest extends DNSInputTest {
    @BeforeEach
    void setUp() throws IOException {
      m_raw = new byte[] {0, 1, 2, 3, 4, 5, (byte) 255, (byte) 255, (byte) 255, (byte) 255};
      // create a new byte array with a prefix and a suffix to be ignored
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.write(42);
      out.write(m_raw);
      out.write(47);
      m_di = new DNSInput(ByteBuffer.wrap(out.toByteArray(), 1, 10));
    }
  }

  @Test
  void initial_state() {
    assertEquals(0, m_di.current());
    assertEquals(10, m_di.remaining());
  }

  @Test
  void jump1() {
    m_di.jump(1);
    assertEquals(1, m_di.current());
    assertEquals(9, m_di.remaining());
  }

  @Test
  void jump2() {
    m_di.jump(9);
    assertEquals(9, m_di.current());
    assertEquals(1, m_di.remaining());
  }

  @Test
  void jump_invalid() {
    assertThrows(IllegalArgumentException.class, () -> m_di.jump(10));
  }

  @ParameterizedTest
  @ValueSource(ints = {5, 10, 0})
  void setActive(int active) {
    m_di.setActive(active);
    assertEquals(0, m_di.current());
    assertEquals(active, m_di.remaining());
  }

  @Test
  void setActive_invalid() {
    assertThrows(IllegalArgumentException.class, () -> m_di.setActive(11));
  }

  @Test
  void clearActive() {
    // first without setting active:
    m_di.clearActive();
    assertEquals(0, m_di.current());
    assertEquals(10, m_di.remaining());

    m_di.setActive(5);
    m_di.clearActive();
    assertEquals(0, m_di.current());
    assertEquals(10, m_di.remaining());
  }

  @Test
  void restore_invalid() {
    assertThrows(IllegalStateException.class, () -> m_di.restore());
  }

  @Test
  void save_restore() {
    m_di.jump(4);
    assertEquals(4, m_di.current());
    assertEquals(6, m_di.remaining());

    m_di.save();
    m_di.jump(0);
    assertEquals(0, m_di.current());
    assertEquals(10, m_di.remaining());

    m_di.restore();
    assertEquals(4, m_di.current());
    assertEquals(6, m_di.remaining());
  }

  @Test
  void save_set_restore() {
    m_di.jump(4);
    assertEquals(4, m_di.current());
    assertEquals(6, m_di.remaining());

    int save = m_di.saveActive();
    assertEquals(10, save);
    assertEquals(6, m_di.remaining());

    m_di.setActive(4);
    assertEquals(4, m_di.remaining());

    m_di.restoreActive(save);
    assertEquals(6, m_di.remaining());
  }

  @Test
  void save_set_restore_boundary() {
    m_di.setActive(4);
    assertEquals(4, m_di.remaining());

    m_di.restoreActive(10);
    assertEquals(10, m_di.remaining());

    assertThrows(IllegalArgumentException.class, () -> m_di.restoreActive(12));
  }

  @Test
  void readU8_basic() throws WireParseException {
    int v1 = m_di.readU8();
    assertEquals(1, m_di.current());
    assertEquals(9, m_di.remaining());
    assertEquals(0, v1);
  }

  @Test
  void readU8_maxval() throws WireParseException {
    m_di.jump(9);
    final int[] v1 = {m_di.readU8()};
    assertEquals(10, m_di.current());
    assertEquals(0, m_di.remaining());
    assertEquals(255, v1[0]);

    assertThrows(WireParseException.class, () -> v1[0] = m_di.readU8());
  }

  @Test
  void readU16_basic() throws WireParseException {
    int v1 = m_di.readU16();
    assertEquals(2, m_di.current());
    assertEquals(8, m_di.remaining());
    assertEquals(1, v1);

    m_di.jump(1);
    v1 = m_di.readU16();
    assertEquals(258, v1);
  }

  @Test
  void readU16_maxval() throws WireParseException {
    m_di.jump(8);
    int v = m_di.readU16();
    assertEquals(10, m_di.current());
    assertEquals(0, m_di.remaining());
    assertEquals(0xFFFF, v);

    assertThrows(
        WireParseException.class,
        () -> {
          m_di.jump(9);
          m_di.readU16();
        });
  }

  @Test
  void readU32_basic() throws WireParseException {
    long v1 = m_di.readU32();
    assertEquals(4, m_di.current());
    assertEquals(6, m_di.remaining());
    assertEquals(66051, v1);
  }

  @Test
  void readU32_maxval() throws WireParseException {
    m_di.jump(6);
    long v = m_di.readU32();
    assertEquals(10, m_di.current());
    assertEquals(0, m_di.remaining());
    assertEquals(0xFFFFFFFFL, v);

    assertThrows(
        WireParseException.class,
        () -> {
          m_di.jump(7);
          m_di.readU32();
        });
  }

  @Test
  void readByteArray_0arg() {
    m_di.jump(1);
    byte[] out = m_di.readByteArray();
    assertEquals(10, m_di.current());
    assertEquals(0, m_di.remaining());
    assertEquals(9, out.length);
    for (int i = 0; i < 9; ++i) {
      assertEquals(m_raw[i + 1], out[i]);
    }
  }

  @Test
  void readByteArray_0arg_boundary() throws WireParseException {
    m_di.jump(9);
    m_di.readU8();
    byte[] out = m_di.readByteArray();
    assertEquals(0, out.length);
  }

  @Test
  void readByteArray_1arg() throws WireParseException {
    byte[] out = m_di.readByteArray(2);
    assertEquals(2, m_di.current());
    assertEquals(8, m_di.remaining());
    assertEquals(2, out.length);
    assertEquals(0, out[0]);
    assertEquals(1, out[1]);
  }

  @Test
  void readByteArray_1arg_boundary() throws WireParseException {
    byte[] out = m_di.readByteArray(10);
    assertEquals(10, m_di.current());
    assertEquals(0, m_di.remaining());
    assertArrayEquals(m_raw, out);
  }

  @Test
  void readByteArray_1arg_invalid() {
    assertThrows(WireParseException.class, () -> m_di.readByteArray(11));
  }

  @Test
  void readByteArray_3arg() throws WireParseException {
    byte[] data = new byte[5];
    m_di.jump(4);

    m_di.readByteArray(data, 1, 4);
    assertEquals(8, m_di.current());
    assertEquals(0, data[0]);
    for (int i = 0; i < 4; ++i) {
      assertEquals(m_raw[i + 4], data[i + 1]);
    }
  }

  @Test
  void readCountedSting() throws WireParseException {
    m_di.jump(1);
    byte[] out = m_di.readCountedString();
    assertEquals(1, out.length);
    assertEquals(3, m_di.current());
    assertEquals(2, out[0]);
  }

  @Test
  void setActive_recursive() throws WireParseException {
    int outer = m_di.saveActive();
    m_di.setActive(3);

    assertEquals(0x00, m_di.readU8());
    assertEquals(2, m_di.remaining());

    int inner = m_di.saveActive();

    m_di.setActive(1);
    assertArrayEquals(new byte[] {0x01}, m_di.readByteArray());

    m_di.restoreActive(inner);

    assertArrayEquals(new byte[] {0x02}, m_di.readByteArray());
    assertEquals(0, m_di.remaining());

    m_di.restoreActive(outer);

    assertEquals(0x03, m_di.readU8());
    assertEquals(6, m_di.remaining());
  }
}
