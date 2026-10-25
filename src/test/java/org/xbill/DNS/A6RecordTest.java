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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class A6RecordTest {
  private Name m_an;
  private Name m_an2;
  private Name m_rn;
  private InetAddress m_addr;
  private String m_addr_string;
  private String m_addr_string_canonical;
  private byte[] m_addr_bytes;
  private int m_prefix_bits;
  private long m_ttl;

  @BeforeEach
  void setUp() throws TextParseException, UnknownHostException {
    m_an = Name.fromString("My.Absolute.Name.");
    m_an2 = Name.fromString("My.Second.Absolute.Name.");
    m_rn = Name.fromString("My.Relative.Name");
    m_addr_string = "2001:0db8:85a3:08d3:1319:8a2e:0370:7334";
    m_addr_string_canonical = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
    m_addr = InetAddress.getByName(m_addr_string);
    m_addr_bytes = m_addr.getAddress();
    m_ttl = 0x13579;
    m_prefix_bits = 9;
  }

  @Test
  void ctor_0arg() {
    A6Record ar = new A6Record();
    assertThat(ar.getName()).isNull();
    assertThat(ar.getType()).isZero();
    assertThat(ar.getDClass()).isZero();
    assertThat(ar.getTTL()).isZero();
  }

  @Test
  void ctor_6arg() throws UnknownHostException {
    A6Record ar = new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, null);
    assertThat(ar.getName()).isEqualTo(m_an);
    assertThat(ar.getType()).isEqualTo(Type.A6);
    assertThat(ar.getDClass()).isEqualTo(DClass.IN);
    assertThat(ar.getTTL()).isEqualTo(m_ttl);
    assertThat(ar.getPrefixBits()).isEqualTo(m_prefix_bits);
    assertThat(ar.getSuffix()).isEqualTo(m_addr);
    assertThat(ar.getPrefix()).isNull();

    // with the prefix name
    ar = new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2);
    assertThat(ar.getName()).isEqualTo(m_an);
    assertThat(ar.getType()).isEqualTo(Type.A6);
    assertThat(ar.getDClass()).isEqualTo(DClass.IN);
    assertThat(ar.getTTL()).isEqualTo(m_ttl);
    assertThat(ar.getPrefixBits()).isEqualTo(m_prefix_bits);
    assertThat(ar.getSuffix()).isEqualTo(m_addr);
    assertThat(ar.getPrefix()).isEqualTo(m_an2);

    // a relative name
    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> new A6Record(m_rn, DClass.IN, m_ttl, m_prefix_bits, m_addr, null));

    // a relative prefix name
    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, m_rn));

    // invalid prefix bits
    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> new A6Record(m_rn, DClass.IN, m_ttl, 0x100, m_addr, null));

    // an IPv4 address - allowed, as these can be written as mapped addresses
    InetAddress address = InetAddress.getByName("192.168.0.1");
    assertDoesNotThrow(() -> new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, address, null));
  }

  @Test
  void rrFromWire() throws IOException {
    // record with no prefix
    DNSOutput dout = new DNSOutput();
    dout.writeU8(0);
    dout.writeByteArray(m_addr_bytes);

    DNSInput din = new DNSInput(dout.toByteArray());
    A6Record ar = new A6Record();
    ar.rrFromWire(din);
    assertThat(ar.getPrefixBits()).isZero();
    assertThat(ar.getSuffix()).isEqualTo(m_addr);
    assertThat(ar.getPrefix()).isNull();

    // record with 9 bit prefix (should result in 15 bytes of the address)
    dout = new DNSOutput();
    dout.writeU8(9);
    dout.writeByteArray(m_addr_bytes, 1, 15);
    dout.writeByteArray(m_an2.toWire());

    din = new DNSInput(dout.toByteArray());
    ar = new A6Record();
    ar.rrFromWire(din);
    assertThat(ar.getPrefixBits()).isEqualTo(9);

    byte[] leadingZeroByteAddress = m_addr_bytes.clone();
    leadingZeroByteAddress[0] = 0;
    InetAddress exp = InetAddress.getByAddress(leadingZeroByteAddress);
    assertThat(ar.getSuffix()).isEqualTo(exp);
    assertThat(ar.getPrefix()).isEqualTo(m_an2);
  }

  @Test
  void rdataFromString() throws IOException {
    // record with no prefix
    Tokenizer t = new Tokenizer("0 " + m_addr_string);
    A6Record ar = new A6Record();
    ar.rdataFromString(t, null);
    assertThat(ar.getPrefixBits()).isZero();
    assertThat(ar.getSuffix()).isEqualTo(m_addr);
    assertThat(ar.getPrefix()).isNull();

    // record with 9 bit prefix.  In contrast to the rrFromWire method,
    // rdataFromString expects the entire 128 bits to be represented
    // in the string
    t = new Tokenizer("9 " + m_addr_string + " " + m_an2);
    ar = new A6Record();
    ar.rdataFromString(t, null);
    assertThat(ar.getPrefixBits()).isEqualTo(9);
    assertThat(ar.getSuffix()).isEqualTo(m_addr);
    assertThat(ar.getPrefix()).isEqualTo(m_an2);

    // record with invalid prefixBits
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> new A6Record().rdataFromString(new Tokenizer("129"), null));

    // record with invalid ipv6 address
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(
            () ->
                new A6Record()
                    .rdataFromString(new Tokenizer("0 " + m_addr_string.substring(4)), null));
  }

  @Test
  void rrToString() {
    A6Record ar = new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2);
    String exp = m_prefix_bits + " " + m_addr_string_canonical + " " + m_an2;
    String out = ar.rrToString();
    assertThat(out).isEqualTo(exp);
  }

  @Test
  void roundtripIPv6MappedIPv4() throws IOException {
    InetAddress mappedAddress = Address.getByAddress("0:0:0:0:0:ffff:192.0.2.1");
    A6Record ar = new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, mappedAddress, m_an2);
    String expectedRdata = "9 0:0:0:0:0:ffff:192.0.2.1 My.Second.Absolute.Name.";
    assertThat(ar.rdataToString()).isEqualTo(expectedRdata);

    DNSOutput out = new DNSOutput();
    ar.rrToWire(out, null, false);

    ar = new A6Record();
    ar.rdataFromString(new Tokenizer(expectedRdata), Name.root);
    assertThat(ar.getPrefixBits()).isEqualTo(m_prefix_bits);
    assertThat(ar.getSuffix()).isEqualTo(mappedAddress);

    ar = new A6Record();
    ar.rrFromWire(new DNSInput(out.toByteArray()));
    assertThat(ar.getPrefixBits()).isEqualTo(m_prefix_bits);
    assertThat(ar.getSuffix()).isEqualTo(mappedAddress);
  }

  @Test
  void rrToWire() {
    // canonical form
    A6Record ar = new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2);
    DNSOutput dout = new DNSOutput();
    dout.writeU8(m_prefix_bits);
    dout.writeByteArray(m_addr_bytes, 1, 15);
    dout.writeByteArray(m_an2.toWireCanonical());

    byte[] exp = dout.toByteArray();

    dout = new DNSOutput();
    ar.rrToWire(dout, null, true);

    assertThat(dout.toByteArray()).containsExactly(exp);

    // case sensitiveform
    dout = new DNSOutput();
    dout.writeU8(m_prefix_bits);
    dout.writeByteArray(m_addr_bytes, 1, 15);
    dout.writeByteArray(m_an2.toWire());

    exp = dout.toByteArray();

    dout = new DNSOutput();
    ar.rrToWire(dout, null, false);
    assertThat(dout.toByteArray()).containsExactly(exp);
  }
}
