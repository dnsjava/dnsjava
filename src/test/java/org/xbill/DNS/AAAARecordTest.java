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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AAAARecordTest {
  private Name m_an;
  private Name m_rn;
  private InetAddress m_addr;
  private String m_addr_string;
  private byte[] m_addr_bytes;
  private long m_ttl;

  @BeforeEach
  void setUp() throws TextParseException, UnknownHostException {
    m_an = Name.fromString("My.Absolute.Name.");
    m_rn = Name.fromString("My.Relative.Name");
    m_addr_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
    m_addr = InetAddress.getByName(m_addr_string);
    m_addr_bytes = m_addr.getAddress();
    m_ttl = 0x13579;
  }

  @Test
  void ctor_0arg() {
    AAAARecord ar = new AAAARecord();
    assertThat(ar.getName()).isNull();
    assertThat(ar.getType()).isZero();
    assertThat(ar.getDClass()).isZero();
    assertThat(ar.getTTL()).isZero();
    assertThat(ar.getAddress()).isNull();
  }

  @Test
  void ctor_4arg() {
    AAAARecord ar = new AAAARecord(m_an, DClass.IN, m_ttl, m_addr);
    assertThat(ar.getName()).isEqualTo(m_an);
    assertThat(ar.getType()).isEqualTo(Type.AAAA);
    assertThat(ar.getDClass()).isEqualTo(DClass.IN);
    assertThat(ar.getTTL()).isEqualTo(m_ttl);
    assertThat(ar.getAddress()).isEqualTo(m_addr);

    // a relative name
    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> new AAAARecord(m_rn, DClass.IN, m_ttl, m_addr));
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2, 3, 5, 15, 17})
  void ctor_4arg_bytes_invalidLength(int len) {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new AAAARecord(m_an, DClass.IN, m_ttl, new byte[len]));
  }

  @Test
  void ctor_v4_address() throws UnknownHostException {
    AAAARecord ar = new AAAARecord(m_an, DClass.IN, m_ttl, InetAddress.getByName("192.168.1.1"));
    assertThat(ar.rrToString()).isEqualTo("0:0:0:0:0:ffff:192.168.1.1");
    DNSOutput out = new DNSOutput();
    ar.rrToWire(out, null, false);
    assertThat(out.toByteArray())
        .isEqualTo(
            new byte[] {
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 192, (byte) 168, 1, 1
            });
  }

  @Test
  void ctor_v4_bytes() {
    AAAARecord ar =
        new AAAARecord(m_an, DClass.IN, m_ttl, new byte[] {(byte) 192, (byte) 168, 1, 1});
    assertThat(ar.rrToString()).isEqualTo("0:0:0:0:0:ffff:192.168.1.1");
    DNSOutput out = new DNSOutput();
    ar.rrToWire(out, null, false);
    assertThat(out.toByteArray())
        .isEqualTo(
            new byte[] {
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 192, (byte) 168, 1, 1
            });
  }

  @Test
  void rrFromWire() throws IOException {
    DNSInput di = new DNSInput(m_addr_bytes);
    AAAARecord ar = new AAAARecord();

    ar.rrFromWire(di);

    assertThat(ar.getAddress()).isEqualTo(m_addr);
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer(m_addr_string);
    AAAARecord ar = new AAAARecord();

    ar.rdataFromString(t, null);

    assertThat(ar.getAddress()).isEqualTo(m_addr);

    // invalid address
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> new AAAARecord().rdataFromString(new Tokenizer("193.160.232.1"), null));
  }

  @Test
  void rrToString() {
    AAAARecord ar = new AAAARecord(m_an, DClass.IN, m_ttl, m_addr);
    assertThat(ar.rrToString()).isEqualTo(m_addr_string);
  }

  @Test
  void rrToWire() {
    AAAARecord ar = new AAAARecord(m_an, DClass.IN, m_ttl, m_addr);

    // canonical
    DNSOutput dout = new DNSOutput();
    ar.rrToWire(dout, null, true);
    assertThat(dout.toByteArray()).containsExactly(m_addr_bytes);

    // case sensitive
    dout = new DNSOutput();
    ar.rrToWire(dout, null, false);
    assertThat(dout.toByteArray()).containsExactly(m_addr_bytes);
  }
}
