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
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DNSOutputTest {
  private DNSOutput m_do;

  @BeforeEach
  void setUp() {
    m_do = new DNSOutput(1);
  }

  @Test
  void default_ctor() {
    m_do = new DNSOutput();
    assertThat(m_do.current()).isZero();
  }

  @Test
  void initial_state() {
    assertThat(m_do.current()).isZero();
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_do.restore());
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_do.jump(1));
  }

  @Test
  void writeU8_basic() {
    m_do.writeU8(1);
    assertThat(m_do.current()).isOne();

    byte[] curr = m_do.toByteArray();
    assertThat(curr.length).isOne();
    assertThat(curr[0]).isOne();
  }

  @Test
  void writeU8_expand() {
    // starts off at 1;
    m_do.writeU8(1);
    m_do.writeU8(2);

    assertThat(m_do.current()).isEqualTo(2);

    byte[] curr = m_do.toByteArray();
    assertThat(curr).hasSize(2);
    assertThat(curr[0]).isOne();
    assertThat(curr[1]).isEqualTo((byte) 2);
  }

  @Test
  void writeU8_max() {
    m_do.writeU8(0xFF);
    byte[] curr = m_do.toByteArray();
    assertThat(curr[0]).isEqualTo((byte) 0xFF);
  }

  @ParameterizedTest
  @ValueSource(
      ints = {
        -1, 256, 0x1FF,
      })
  void writeU8_toobig(int val) {
    assertThatThrownBy(() -> m_do.writeU8(val)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void writeU16_basic() {
    m_do.writeU16(0x100);
    assertThat(m_do.current()).isEqualTo(2);

    byte[] curr = m_do.toByteArray();
    assertThat(curr).hasSize(2);
    assertThat(curr[0]).isOne();
    assertThat(curr[1]).isZero();
  }

  @Test
  void writeU16_max() {
    m_do.writeU16(0xFFFF);
    byte[] curr = m_do.toByteArray();
    assertThat(curr[0]).isEqualTo((byte) 0xFF);
    assertThat(curr[1]).isEqualTo((byte) 0XFF);
  }

  @ParameterizedTest
  @ValueSource(
      ints = {
        -1,
        0xFFFF + 1,
        0x1FFFF,
      })
  void writeU16_toobig(int val) {
    assertThatThrownBy(() -> m_do.writeU16(val)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void writeU32_basic() {
    m_do.writeU32(0x11001011);
    assertThat(m_do.current()).isEqualTo(4);

    byte[] curr = m_do.toByteArray();
    assertThat(curr).hasSize(4);
    assertThat(curr[0]).isEqualTo((byte) 0x11);
    assertThat(curr[1]).isEqualTo((byte) 0x00);
    assertThat(curr[2]).isEqualTo((byte) 0x10);
    assertThat(curr[3]).isEqualTo((byte) 0x11);
  }

  @Test
  void writeU32_max() {
    m_do.writeU32(0xFFFFFFFFL);
    byte[] curr = m_do.toByteArray();
    assertThat(curr[0]).isEqualTo((byte) 0xFF);
    assertThat(curr[1]).isEqualTo((byte) 0XFF);
    assertThat(curr[2]).isEqualTo((byte) 0XFF);
    assertThat(curr[3]).isEqualTo((byte) 0XFF);
  }

  @ParameterizedTest
  @ValueSource(
      longs = {
        -1L,
        0xffff_ffffL + 1L,
        0x1_ffff_ffffL,
      })
  void writeU32_toobig(long val) {
    assertThatThrownBy(() -> m_do.writeU32(val)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void jump_basic() {
    m_do.writeU32(0x11223344L);
    assertThat(m_do.current()).isEqualTo(4);
    m_do.jump(2);
    assertThat(m_do.current()).isEqualTo(2);
    m_do.writeU8(0x99);
    byte[] curr = m_do.toByteArray();
    assertThat(curr).hasSize(3);
    assertThat(curr[0]).isEqualTo((byte) 0x11);
    assertThat(curr[1]).isEqualTo((byte) 0x22);
    assertThat(curr[2]).isEqualTo((byte) 0x99);
  }

  @Test
  void writeByteArray_1arg() {
    byte[] in = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x12, (byte) 0x34};
    m_do.writeByteArray(in);
    assertThat(m_do.current()).isEqualTo(5);
    byte[] curr = m_do.toByteArray();
    assertThat(curr).containsExactly(in);
  }

  @Test
  void writeByteArray_3arg() {
    byte[] in = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x12, (byte) 0x34};
    m_do.writeByteArray(in, 2, 3);
    assertThat(m_do.current()).isEqualTo(3);
    byte[] exp = {in[2], in[3], in[4]};
    byte[] curr = m_do.toByteArray();
    assertThat(curr).containsExactly(exp);
  }

  @Test
  void writeCountedString_basic() {
    byte[] in = {'h', 'e', 'l', 'L', '0'};
    m_do.writeCountedString(in);
    assertThat(m_do.current()).isEqualTo(in.length + 1);
    byte[] curr = m_do.toByteArray();
    byte[] exp = {(byte) in.length, in[0], in[1], in[2], in[3], in[4]};
    assertThat(curr).containsExactly(exp);
  }

  @Test
  void writeCountedString_empty() {
    byte[] in = {};
    m_do.writeCountedString(in);
    assertThat(m_do.current()).isEqualTo(in.length + 1);
    byte[] curr = m_do.toByteArray();
    byte[] exp = {(byte) in.length};
    assertThat(curr).containsExactly(exp);
  }

  @Test
  void writeCountedString_toobig() {
    byte[] in = new byte[256];
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> m_do.writeCountedString(in));
  }

  @Test
  void save_restore() {
    m_do.writeU32(0x12345678L);
    assertThat(m_do.current()).isEqualTo(4);
    m_do.save();
    m_do.writeU16(0xABCD);
    assertThat(m_do.current()).isEqualTo(6);
    m_do.restore();
    assertThat(m_do.current()).isEqualTo(4);
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_do.restore());
  }
}
