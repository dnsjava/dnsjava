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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ARecordTest {
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
    m_addr_string = "193.160.232.5";
    m_addr = InetAddress.getByName(m_addr_string);
    m_addr_bytes = m_addr.getAddress();
    m_ttl = 0x13579;
  }

  @Test
  void ctor_0arg() throws UnknownHostException {
    ARecord ar = new ARecord();
    assertThat(ar.getName()).isNull();
    assertThat(ar.getType()).isZero();
    assertThat(ar.getDClass()).isZero();
    assertThat(ar.getTTL()).isZero();
    assertThat(ar.getAddress()).isEqualTo(InetAddress.getByName("0.0.0.0"));
  }

  @Test
  void ctor_4arg() throws UnknownHostException {
    ARecord ar = new ARecord(m_an, DClass.IN, m_ttl, m_addr);
    assertThat(ar.getName()).isEqualTo(m_an);
    assertThat(ar.getType()).isEqualTo(Type.A);
    assertThat(ar.getDClass()).isEqualTo(DClass.IN);
    assertThat(ar.getTTL()).isEqualTo(m_ttl);
    assertThat(ar.getAddress()).isEqualTo(m_addr);

    // a relative name
    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> new ARecord(m_rn, DClass.IN, m_ttl, m_addr));

    // an IPv6 address
    InetAddress address = InetAddress.getByName("2001:0db8:85a3:08d3:1319:8a2e:0370:7334");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new ARecord(m_an, DClass.IN, m_ttl, address));
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2, 3, 5, 16})
  void ctor_4arg_bytes_invalidLength(int len) {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new ARecord(m_an, DClass.IN, m_ttl, new byte[len]));
  }

  @Test
  void ctor_4arg_bytes() {
    ARecord ar = new ARecord(m_an, DClass.IN, m_ttl, m_addr_bytes);
    assertThat(ar.getName()).isEqualTo(m_an);
    assertThat(ar.getType()).isEqualTo(Type.A);
    assertThat(ar.getDClass()).isEqualTo(DClass.IN);
    assertThat(ar.getTTL()).isEqualTo(m_ttl);
    assertThat(ar.getAddress()).isEqualTo(m_addr);

    // a relative name
    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> new ARecord(m_rn, DClass.IN, m_ttl, m_addr));
  }

  @Test
  void rrFromWire() throws IOException {
    DNSInput di = new DNSInput(m_addr_bytes);
    ARecord ar = new ARecord();

    ar.rrFromWire(di);

    assertThat(ar.getAddress()).isEqualTo(m_addr);
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer(m_addr_string);
    ARecord ar = new ARecord();

    ar.rdataFromString(t, null);

    assertThat(ar.getAddress()).isEqualTo(m_addr);

    // invalid address
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> new ARecord().rdataFromString(new Tokenizer("193.160.232"), null));
  }

  @Test
  void rrToString() {
    ARecord ar = new ARecord(m_an, DClass.IN, m_ttl, m_addr);
    assertThat(ar.rrToString()).isEqualTo(m_addr_string);
  }

  @Test
  void rrToWire() {
    ARecord ar = new ARecord(m_an, DClass.IN, m_ttl, m_addr);
    DNSOutput dout = new DNSOutput();

    ar.rrToWire(dout, null, true);
    assertThat(dout.toByteArray()).containsExactly(m_addr_bytes);

    dout = new DNSOutput();
    ar.rrToWire(dout, null, false);
    assertThat(dout.toByteArray()).containsExactly(m_addr_bytes);
  }

  @Test
  void testSerializable() throws IOException, ClassNotFoundException {
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
      try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
        ARecord expected = new ARecord(Name.root, DClass.IN, 60, m_addr);
        oos.writeObject(expected);
        try (ObjectInputStream ois =
            new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
          Record actual = (Record) ois.readObject();
          assertThat(actual).isEqualTo(expected);
        }
      }
    }
  }
}
