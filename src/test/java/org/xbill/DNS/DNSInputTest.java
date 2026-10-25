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
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

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
    assertThat(m_di.current()).isZero();
    assertThat(m_di.remaining()).isEqualTo(10);
  }

  @Test
  void jump1() {
    m_di.jump(1);
    assertThat(m_di.current()).isOne();
    assertThat(m_di.remaining()).isEqualTo(9);
  }

  @Test
  void jump2() {
    m_di.jump(9);
    assertThat(m_di.current()).isEqualTo(9);
    assertThat(m_di.remaining()).isOne();
  }

  @Test
  void jump_invalid() {
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_di.jump(10));
  }

  @ParameterizedTest
  @ValueSource(ints = {5, 10, 0})
  void setActive(int active) {
    m_di.setActive(active);
    assertThat(m_di.current()).isZero();
    assertThat(m_di.remaining()).isEqualTo(active);
  }

  @Test
  void setActive_invalid() {
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_di.setActive(11));
  }

  @Test
  void clearActive() {
    // first without setting active:
    m_di.clearActive();
    assertThat(m_di.current()).isZero();
    assertThat(m_di.remaining()).isEqualTo(10);

    m_di.setActive(5);
    m_di.clearActive();
    assertThat(m_di.current()).isZero();
    assertThat(m_di.remaining()).isEqualTo(10);
  }

  @Test
  void restore_invalid() {
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_di.restore());
  }

  @Test
  void save_restore() {
    m_di.jump(4);
    assertThat(m_di.current()).isEqualTo(4);
    assertThat(m_di.remaining()).isEqualTo(6);

    m_di.save();
    m_di.jump(0);
    assertThat(m_di.current()).isZero();
    assertThat(m_di.remaining()).isEqualTo(10);

    m_di.restore();
    assertThat(m_di.current()).isEqualTo(4);
    assertThat(m_di.remaining()).isEqualTo(6);
  }

  @Test
  void save_set_restore() {
    m_di.jump(4);
    assertThat(m_di.current()).isEqualTo(4);
    assertThat(m_di.remaining()).isEqualTo(6);

    int save = m_di.saveActive();
    assertThat(save).isEqualTo(10);
    assertThat(m_di.remaining()).isEqualTo(6);

    m_di.setActive(4);
    assertThat(m_di.remaining()).isEqualTo(4);

    m_di.restoreActive(save);
    assertThat(m_di.remaining()).isEqualTo(6);
  }

  @Test
  void save_set_restore_boundary() {
    m_di.setActive(4);
    assertThat(m_di.remaining()).isEqualTo(4);

    m_di.restoreActive(10);
    assertThat(m_di.remaining()).isEqualTo(10);

    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> m_di.restoreActive(12));
  }

  @Test
  void readU8_basic() throws WireParseException {
    int v1 = m_di.readU8();
    assertThat(m_di.current()).isOne();
    assertThat(m_di.remaining()).isEqualTo(9);
    assertThat(v1).isZero();
  }

  @Test
  void readU8_maxval() throws WireParseException {
    m_di.jump(9);
    final int[] v1 = {m_di.readU8()};
    assertThat(m_di.current()).isEqualTo(10);
    assertThat(m_di.remaining()).isZero();
    assertThat(v1[0]).isEqualTo(255);

    assertThatExceptionOfType(WireParseException.class).isThrownBy(() -> v1[0] = m_di.readU8());
  }

  @Test
  void readU16_basic() throws WireParseException {
    int v1 = m_di.readU16();
    assertThat(m_di.current()).isEqualTo(2);
    assertThat(m_di.remaining()).isEqualTo(8);
    assertThat(v1).isOne();

    m_di.jump(1);
    v1 = m_di.readU16();
    assertThat(v1).isEqualTo(258);
  }

  @Test
  void readU16_maxval() throws WireParseException {
    m_di.jump(8);
    int v = m_di.readU16();
    assertThat(m_di.current()).isEqualTo(10);
    assertThat(m_di.remaining()).isZero();
    assertThat(v).isEqualTo(0xFFFF);

    assertThatExceptionOfType(WireParseException.class)
        .isThrownBy(
            () -> {
              m_di.jump(9);
              m_di.readU16();
            });
  }

  @Test
  void readU32_basic() throws WireParseException {
    long v1 = m_di.readU32();
    assertThat(m_di.current()).isEqualTo(4);
    assertThat(m_di.remaining()).isEqualTo(6);
    assertThat(v1).isEqualTo(66051);
  }

  @Test
  void readU32_maxval() throws WireParseException {
    m_di.jump(6);
    long v = m_di.readU32();
    assertThat(m_di.current()).isEqualTo(10);
    assertThat(m_di.remaining()).isZero();
    assertThat(v).isEqualTo(0xFFFFFFFFL);

    assertThatExceptionOfType(WireParseException.class)
        .isThrownBy(
            () -> {
              m_di.jump(7);
              m_di.readU32();
            });
  }

  @Test
  void readByteArray_0arg() {
    m_di.jump(1);
    byte[] out = m_di.readByteArray();
    assertThat(m_di.current()).isEqualTo(10);
    assertThat(m_di.remaining()).isZero();
    assertThat(out).hasSize(9);
    for (int i = 0; i < 9; ++i) {
      assertThat(out[i]).isEqualTo(m_raw[i + 1]);
    }
  }

  @Test
  void readByteArray_0arg_boundary() throws WireParseException {
    m_di.jump(9);
    m_di.readU8();
    byte[] out = m_di.readByteArray();
    assertThat(out).isEmpty();
  }

  @Test
  void readByteArray_1arg() throws WireParseException {
    byte[] out = m_di.readByteArray(2);
    assertThat(m_di.current()).isEqualTo(2);
    assertThat(m_di.remaining()).isEqualTo(8);
    assertThat(out).hasSize(2);
    assertThat(out[0]).isZero();
    assertThat(out[1]).isOne();
  }

  @Test
  void readByteArray_1arg_boundary() throws WireParseException {
    byte[] out = m_di.readByteArray(10);
    assertThat(m_di.current()).isEqualTo(10);
    assertThat(m_di.remaining()).isZero();
    assertThat(out).containsExactly(m_raw);
  }

  @Test
  void readByteArray_1arg_invalid() {
    assertThatExceptionOfType(WireParseException.class).isThrownBy(() -> m_di.readByteArray(11));
  }

  @Test
  void readByteArray_3arg() throws WireParseException {
    byte[] data = new byte[5];
    m_di.jump(4);

    m_di.readByteArray(data, 1, 4);
    assertThat(m_di.current()).isEqualTo(8);
    assertThat(data[0]).isZero();
    for (int i = 0; i < 4; ++i) {
      assertThat(data[i + 1]).isEqualTo(m_raw[i + 4]);
    }
  }

  @Test
  void readCountedSting() throws WireParseException {
    m_di.jump(1);
    byte[] out = m_di.readCountedString();
    assertThat(out.length).isOne();
    assertThat(m_di.current()).isEqualTo(3);
    assertThat(out[0]).isEqualTo((byte) 2);
  }

  @Test
  void setActive_recursive() throws WireParseException {
    int outer = m_di.saveActive();
    m_di.setActive(3);

    assertThat(m_di.readU8()).isEqualTo(0x00);
    assertThat(m_di.remaining()).isEqualTo(2);

    int inner = m_di.saveActive();

    m_di.setActive(1);
    assertThat(m_di.readByteArray()).containsExactly(new byte[] {0x01});

    m_di.restoreActive(inner);

    assertThat(m_di.readByteArray()).containsExactly(new byte[] {0x02});
    assertThat(m_di.remaining()).isZero();

    m_di.restoreActive(outer);

    assertThat(m_di.readU8()).isEqualTo(0x03);
    assertThat(m_di.remaining()).isEqualTo(6);
  }
}
