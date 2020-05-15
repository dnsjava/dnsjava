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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

class ReverseMapTest {
  private final String ipv4Addr = "192.168.0.1";
  private final Name ipv4arpa = Name.fromConstantString("1.0.168.192.in-addr.arpa.");
  private final Name ipv6arpa =
      Name.fromConstantString(
          "4.3.3.7.0.7.3.0.E.2.A.8.9.1.3.1.3.D.8.0.3.A.5.8.8.B.D.0.1.0.0.2.ip6.arpa.");
  private final String ipv6addr = "2001:db8:85a3:8d3:1319:8a2e:370:7334";

  @Test
  void fromAddress_ipv4() throws UnknownHostException {
    assertEquals(ipv4arpa, ReverseMap.fromAddress(ipv4Addr));

    assertEquals(ipv4arpa, ReverseMap.fromAddress(ipv4Addr, Address.IPv4));
    assertEquals(ipv4arpa, ReverseMap.fromAddress(InetAddress.getByName(ipv4Addr)));
    assertEquals(
        ipv4arpa, ReverseMap.fromAddress(new byte[] {(byte) 192, (byte) 168, (byte) 0, (byte) 1}));
    assertEquals(ipv4arpa, ReverseMap.fromAddress(new int[] {192, 168, 0, 1}));
  }

  @Test
  void fromAddress_ipv6() throws UnknownHostException {
    byte[] dat =
        new byte[] {
          (byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 133, (byte) 163, (byte) 8, (byte) 211,
          (byte) 19, (byte) 25, (byte) 138, (byte) 46, (byte) 3, (byte) 112, (byte) 115, (byte) 52
        };
    int[] idat = new int[] {32, 1, 13, 184, 133, 163, 8, 211, 19, 25, 138, 46, 3, 112, 115, 52};

    assertEquals(ipv6arpa, ReverseMap.fromAddress(ipv6addr, Address.IPv6));
    assertEquals(ipv6arpa, ReverseMap.fromAddress(InetAddress.getByName(ipv6addr)));
    assertEquals(ipv6arpa, ReverseMap.fromAddress(dat));
    assertEquals(ipv6arpa, ReverseMap.fromAddress(idat));
  }

  @Test
  void fromAddress_invalid() {
    assertThrows(UnknownHostException.class, () -> ReverseMap.fromAddress("A.B.C.D", Address.IPv4));
    assertThrows(IllegalArgumentException.class, () -> ReverseMap.fromAddress(new byte[0]));
    assertThrows(IllegalArgumentException.class, () -> ReverseMap.fromAddress(new byte[3]));
    assertThrows(IllegalArgumentException.class, () -> ReverseMap.fromAddress(new byte[5]));
    assertThrows(IllegalArgumentException.class, () -> ReverseMap.fromAddress(new byte[15]));
    assertThrows(IllegalArgumentException.class, () -> ReverseMap.fromAddress(new byte[17]));

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          int[] dat = new int[] {0, 1, 2, 256};
          ReverseMap.fromAddress(dat);
        });
  }

  @Test
  void fromName_ipv4_valid() throws TextParseException, UnknownHostException {
    assertEquals(ipv4Addr, ReverseMap.fromName(ipv4arpa).getHostAddress());
    assertEquals("192.168.0.0", ReverseMap.fromName("168.192.in-addr.arpa.").getHostAddress());
  }

  @Test
  void fromName_ipv6_valid() throws TextParseException, UnknownHostException {
    assertEquals(ipv6addr, ReverseMap.fromName(ipv6arpa).getHostAddress());
    assertEquals(
        "2001:db8:0:0:0:0:0:0", ReverseMap.fromName("8.B.D.0.1.0.0.2.ip6.arpa.").getHostAddress());
    assertEquals(
        "2001:d00:0:0:0:0:0:0", ReverseMap.fromName("D.0.1.0.0.2.ip6.arpa.").getHostAddress());
    assertEquals(
        "2001:db0:0:0:0:0:0:0", ReverseMap.fromName("B.D.0.1.0.0.2.ip6.arpa.").getHostAddress());
  }

  @Test
  void fromNameInvalid() {
    assertThrows(UnknownHostException.class, () -> ReverseMap.fromName("host.example.com."));

    assertThrows(UnknownHostException.class, () -> ReverseMap.fromName("ip6.arpa."));
    assertThrows(UnknownHostException.class, () -> ReverseMap.fromName("caffee.ip6.arpa."));
    assertThrows(
        UnknownHostException.class,
        () ->
            ReverseMap.fromName(
                "1.4.3.3.7.0.7.3.0.E.2.A.8.9.1.3.1.3.D.8.0.3.A.5.8.8.B.D.0.1.0.0.2.ip6.arpa."));

    assertThrows(UnknownHostException.class, () -> ReverseMap.fromName("in-addr.arpa."));
    assertThrows(UnknownHostException.class, () -> ReverseMap.fromName("caffee.in-addr.arpa."));
    assertThrows(UnknownHostException.class, () -> ReverseMap.fromName("1.2.3.4.5.in-addr.arpa."));
  }
}
