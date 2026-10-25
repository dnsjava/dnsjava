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
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HeaderTest {
  private Header m_h;

  @BeforeEach
  void setUp() {
    m_h = new Header(0xABCD); // 43981
  }

  @Test
  void fixture_state() {
    assertThat(m_h.getID()).isEqualTo(0xABCD);

    boolean[] flags = m_h.getFlags();
    for (boolean flag : flags) {
      assertThat(flag).isFalse();
    }
    assertThat(m_h.getRcode()).isZero();
    assertThat(m_h.getOpcode()).isZero();
    assertThat(m_h.getCount(0)).isZero();
    assertThat(m_h.getCount(1)).isZero();
    assertThat(m_h.getCount(2)).isZero();
    assertThat(m_h.getCount(3)).isZero();
  }

  @Test
  void ctor_0arg() {
    m_h = new Header();
    assertThat(0 <= m_h.getID() && m_h.getID() < 0xFFFF).isTrue();

    boolean[] flags = m_h.getFlags();
    for (boolean flag : flags) {
      assertThat(flag).isFalse();
    }
    assertThat(m_h.getRcode()).isZero();
    assertThat(m_h.getOpcode()).isZero();
    assertThat(m_h.getCount(0)).isZero();
    assertThat(m_h.getCount(1)).isZero();
    assertThat(m_h.getCount(2)).isZero();
    assertThat(m_h.getCount(3)).isZero();
  }

  @Test
  void ctor_DNSInput() throws IOException {
    byte[] raw = {
      (byte) 0x12,
      (byte) 0xAB, // ID
      (byte) 0x8F,
      (byte) 0xBD, // flags: 1 0001 1 1 1 1 011 1101
      (byte) 0x65,
      (byte) 0x1C, // QDCOUNT
      (byte) 0x10,
      (byte) 0xF0, // ANCOUNT
      (byte) 0x98,
      (byte) 0xBA, // NSCOUNT
      (byte) 0x71,
      (byte) 0x90
    }; // ARCOUNT

    m_h = new Header(new DNSInput(raw));

    assertThat(m_h.getID()).isEqualTo(0x12AB);

    boolean[] flags = m_h.getFlags();

    assertThat(flags[0]).isTrue();

    assertThat(m_h.getOpcode()).isOne();

    assertThat(flags[5]).isTrue();

    assertThat(flags[6]).isTrue();

    assertThat(flags[7]).isTrue();

    assertThat(flags[8]).isTrue();

    assertThat(flags[9]).isFalse();
    assertThat(flags[10]).isTrue();
    assertThat(flags[11]).isTrue();

    assertThat(m_h.getRcode()).isEqualTo(0xD);

    assertThat(m_h.getCount(0)).isEqualTo(0x651C);
    assertThat(m_h.getCount(1)).isEqualTo(0x10F0);
    assertThat(m_h.getCount(2)).isEqualTo(0x98BA);
    assertThat(m_h.getCount(3)).isEqualTo(0x7190);
  }

  @Test
  void toWire() throws IOException {
    byte[] raw = {
      (byte) 0x12,
      (byte) 0xAB, // ID
      (byte) 0x8F,
      (byte) 0xBD, // flags: 1 0001 1 1 1 1 011 1101
      (byte) 0x65,
      (byte) 0x1C, // QDCOUNT
      (byte) 0x10,
      (byte) 0xF0, // ANCOUNT
      (byte) 0x98,
      (byte) 0xBA, // NSCOUNT
      (byte) 0x71,
      (byte) 0x90
    }; // ARCOUNT

    m_h = new Header(raw);

    DNSOutput dout = new DNSOutput();
    m_h.toWire(dout);

    byte[] out = dout.toByteArray();

    assertThat(out).hasSize(12);
    for (int i = 0; i < out.length; ++i) {
      assertThat(out[i]).isEqualTo(raw[i]);
    }

    m_h.setOpcode(0xA); // 1010
    assertThat(m_h.getOpcode()).isEqualTo(0xA);
    m_h.setRcode(0x7); // 0111

    // flags is now: 1101 0111 1011 0111

    raw[2] = (byte) 0xD7;
    raw[3] = (byte) 0xB7;

    out = m_h.toWire();

    assertThat(out).hasSize(12);
    for (int i = 0; i < out.length; ++i) {
      assertThat(out[i]).as("i=" + i).isEqualTo(raw[i]);
    }
  }

  @Test
  void flags() {
    m_h.setFlag(0);
    m_h.setFlag(5);
    assertThat(m_h.getFlag(0)).isTrue();
    assertThat(m_h.getFlags()[0]).isTrue();
    assertThat(m_h.getFlag(5)).isTrue();
    assertThat(m_h.getFlags()[5]).isTrue();

    m_h.unsetFlag(0);
    assertThat(m_h.getFlag(0)).isFalse();
    assertThat(m_h.getFlags()[0]).isFalse();
    assertThat(m_h.getFlag(5)).isTrue();
    assertThat(m_h.getFlags()[5]).isTrue();

    m_h.unsetFlag(5);
    assertThat(m_h.getFlag(0)).isFalse();
    assertThat(m_h.getFlags()[0]).isFalse();
    assertThat(m_h.getFlag(5)).isFalse();
    assertThat(m_h.getFlags()[5]).isFalse();

    boolean[] flags = m_h.getFlags();
    for (int i = 0; i < flags.length; ++i) {
      if ((i > 0 && i < 5) || i > 11) {
        continue;
      }
      assertThat(flags[i]).isFalse();
    }
  }

  @Test
  void flags_invalid() {
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.setFlag(-1));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.setFlag(1));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.setFlag(16));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.unsetFlag(-1));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.unsetFlag(13));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.unsetFlag(16));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.getFlag(-1));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.getFlag(4));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.getFlag(16));
  }

  @Test
  void ID() {
    assertThat(m_h.getID()).isEqualTo(0xABCD);

    m_h = new Header();

    int id = m_h.getID();
    assertThat(m_h.getID()).isEqualTo(id);
    assertThat(id).isNotNegative().isLessThanOrEqualTo(0xffff);

    m_h.setID(0xDCBA);
    assertThat(m_h.getID()).isEqualTo(0xDCBA);
  }

  @Test
  void setID_invalid() {
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.setID(0x10000));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.setID(-1));
  }

  @Test
  void Rcode() {
    assertThat(m_h.getRcode()).isZero();

    m_h.setRcode(0xA); // 1010
    assertThat(m_h.getRcode()).isEqualTo(0xA);
    for (int i = 0; i < 12; ++i) {
      if ((i > 0 && i < 5) || i > 11) {
        continue;
      }
      assertThat(m_h.getFlag(i)).isFalse();
    }
  }

  @Test
  void setRcode_invalid() {
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.setRcode(-1));
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.setRcode(0x100));
  }

  @Test
  void Opcode() {
    assertThat(m_h.getOpcode()).isZero();

    m_h.setOpcode(0xE); // 1110
    assertThat(m_h.getOpcode()).isEqualTo(0xE);

    assertThat(m_h.getFlag(0)).isFalse();
    for (int i = 5; i < 12; ++i) {
      assertThat(m_h.getFlag(i)).isFalse();
    }
    assertThat(m_h.getRcode()).isZero();
  }

  @Test
  void setOpcode_invalid() {
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.setOpcode(-1));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> m_h.setOpcode(0x100));
  }

  @Test
  void Count() {
    m_h.setCount(2, 0x1E);
    assertThat(m_h.getCount(0)).isZero();
    assertThat(m_h.getCount(1)).isZero();
    assertThat(m_h.getCount(2)).isEqualTo(0x1E);
    assertThat(m_h.getCount(3)).isZero();

    m_h.incCount(0);
    assertThat(m_h.getCount(0)).isOne();

    m_h.decCount(2);
    assertThat(m_h.getCount(2)).isEqualTo(0x1E - 1);
  }

  @Test
  void setCount_invalid() {
    assertThatExceptionOfType(ArrayIndexOutOfBoundsException.class)
        .isThrownBy(() -> m_h.setCount(-1, 0));
    assertThatExceptionOfType(ArrayIndexOutOfBoundsException.class)
        .isThrownBy(() -> m_h.setCount(4, 0));

    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_h.setCount(0, -1));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> m_h.setCount(3, 0x10000));
  }

  @Test
  void getCount_invalid() {
    assertThatExceptionOfType(ArrayIndexOutOfBoundsException.class)
        .isThrownBy(() -> m_h.getCount(-1));
    assertThatExceptionOfType(ArrayIndexOutOfBoundsException.class)
        .isThrownBy(() -> m_h.getCount(4));
  }

  @Test
  void incCount_invalid() {
    m_h.setCount(1, 0xFFFF);
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_h.incCount(1));
  }

  @Test
  void decCount_invalid() {
    m_h.setCount(2, 0);
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_h.decCount(2));
  }

  @Test
  void test_toString() {
    m_h.setOpcode(Opcode.value("STATUS"));
    m_h.setRcode(Rcode.value("NXDOMAIN"));
    m_h.setFlag(0); // qr
    m_h.setFlag(7); // rd
    m_h.setFlag(8); // ra
    m_h.setFlag(11); // cd
    m_h.setCount(1, 0xFF);
    m_h.setCount(2, 0x0A);

    String text = m_h.toString();

    assertThat(text)
        .contains("id: 43981")
        .contains("opcode: STATUS")
        .contains("status: NXDOMAIN")
        .contains(" qr ")
        .contains(" rd ")
        .contains(" ra ")
        .contains(" cd ")
        .contains("qd: 0 ")
        .contains("an: 255 ")
        .contains("au: 10 ")
        .contains("ad: 0 ");
  }

  @Test
  void test_clone() {
    m_h.setOpcode(Opcode.value("IQUERY"));
    m_h.setRcode(Rcode.value("SERVFAIL"));
    m_h.setFlag(0); // qr
    m_h.setFlag(7); // rd
    m_h.setFlag(8); // ra
    m_h.setFlag(11); // cd
    m_h.setCount(1, 0xFF);
    m_h.setCount(2, 0x0A);

    Header h2 = m_h.clone();

    assertNotSame(m_h, h2);
    assertThat(h2.getID()).isEqualTo(m_h.getID());
    for (int i = 0; i < 16; ++i) {
      if ((i > 0 && i < 5) || i > 11) {
        continue;
      }
      assertThat(h2.getFlag(i)).isEqualTo(m_h.getFlag(i));
    }
    for (int i = 0; i < 4; ++i) {
      assertThat(h2.getCount(i)).isEqualTo(m_h.getCount(i));
    }

    h2.setCount(1, 1);
    h2.setCount(2, 1);
    assertThat(m_h.getCount(1)).isEqualTo(0xFF);
    assertThat(m_h.getCount(2)).isEqualTo(0x0A);
  }
}
