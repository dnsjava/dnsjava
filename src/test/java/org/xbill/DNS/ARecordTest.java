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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
    assertNull(ar.getName());
    assertEquals(0, ar.getType());
    assertEquals(0, ar.getDClass());
    assertEquals(0, ar.getTTL());
    assertEquals(InetAddress.getByName("0.0.0.0"), ar.getAddress());
  }

  @Test
  void getObject() {
    ARecord ar = new ARecord();
    Record r = ar.getObject();
    assertTrue(r instanceof ARecord);
  }

  @Test
  void ctor_4arg() {
    ARecord ar = new ARecord(m_an, DClass.IN, m_ttl, m_addr);
    assertEquals(m_an, ar.getName());
    assertEquals(Type.A, ar.getType());
    assertEquals(DClass.IN, ar.getDClass());
    assertEquals(m_ttl, ar.getTTL());
    assertEquals(m_addr, ar.getAddress());

    // a relative name
    assertThrows(RelativeNameException.class, () -> new ARecord(m_rn, DClass.IN, m_ttl, m_addr));

    // an IPv6 address
    try {
      new ARecord(
          m_an, DClass.IN, m_ttl, InetAddress.getByName("2001:0db8:85a3:08d3:1319:8a2e:0370:7334"));
      fail("IllegalArgumentException not thrown");
    } catch (IllegalArgumentException e) {
    } catch (UnknownHostException e) {
      fail(e.getMessage());
    }
  }

  @Test
  void rrFromWire() throws IOException {
    DNSInput di = new DNSInput(m_addr_bytes);
    ARecord ar = new ARecord();

    ar.rrFromWire(di);

    assertEquals(m_addr, ar.getAddress());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer(m_addr_string);
    ARecord ar = new ARecord();

    ar.rdataFromString(t, null);

    assertEquals(m_addr, ar.getAddress());

    // invalid address
    assertThrows(
        TextParseException.class,
        () -> new ARecord().rdataFromString(new Tokenizer("193.160.232"), null));
  }

  @Test
  void rrToString() {
    ARecord ar = new ARecord(m_an, DClass.IN, m_ttl, m_addr);
    assertEquals(m_addr_string, ar.rrToString());
  }

  @Test
  void rrToWire() {
    ARecord ar = new ARecord(m_an, DClass.IN, m_ttl, m_addr);
    DNSOutput dout = new DNSOutput();

    ar.rrToWire(dout, null, true);
    assertArrayEquals(m_addr_bytes, dout.toByteArray());

    dout = new DNSOutput();
    ar.rrToWire(dout, null, false);
    assertArrayEquals(m_addr_bytes, dout.toByteArray());
  }
}
