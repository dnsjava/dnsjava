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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentMatchers;
import org.mockito.stubbing.Answer;

class AddressTest {
  @Test
  void toByteArray_invalid() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> Address.toByteArray("doesn't matter", 3));
  }

  @Test
  void toByteArray_IPv4() {
    byte[] exp = new byte[] {(byte) 198, (byte) 121, (byte) 10, (byte) 234};
    byte[] ret = Address.toByteArray("198.121.10.234", Address.IPv4);
    assertThat(ret).containsExactly(exp);

    exp = new byte[] {0, 0, 0, 0};
    ret = Address.toByteArray("0.0.0.0", Address.IPv4);
    assertThat(ret).containsExactly(exp);

    exp = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    ret = Address.toByteArray("255.255.255.255", Address.IPv4);
    assertThat(ret).containsExactly(exp);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "A.B.C.D",
        "128...",
        "128.121",
        "128.111.8",
        "128.198.10.",
        "128.121.90..10",
        "128.121..90.10",
        "128..121.90.10",
        ".128.121.90.10",
        "128.121.90.256",
        "128.121.256.10",
        "128.256.90.10",
        "256.121.90.10",
        "128.121.90.-1",
        "128.121.-1.10",
        "128.-1.90.10",
        "-1.121.90.10",
        "120.121.90.10.10",
        "120.121.90.010",
        "120.121.090.10",
        "120.021.90.10",
        "020.121.90.10",
        "1120.121.90.10",
        "120.2121.90.10",
        "120.121.4190.10",
        "120.121.190.1000",
        "",
      })
  void toByteArray_IPv4_invalid(String address) {
    assertThat(Address.toByteArray(address, Address.IPv4)).isNull();
  }

  @Test
  void toByteArray_IPv6() {
    byte[] exp = {
      (byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 133, (byte) 163, (byte) 8, (byte) 211,
      (byte) 19, (byte) 25, (byte) 138, (byte) 46, (byte) 3, (byte) 112, (byte) 115, (byte) 52
    };
    byte[] ret = Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e:0370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);
    ret = Address.toByteArray("2001:db8:85a3:8d3:1319:8a2e:370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);
    ret = Address.toByteArray("2001:DB8:85A3:8D3:1319:8A2E:370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    exp = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ret = Address.toByteArray("0:0:0:0:0:0:0:0", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    exp =
        new byte[] {
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF
        };
    ret = Address.toByteArray("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    exp =
        new byte[] {
          (byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 0, (byte) 0, (byte) 8, (byte) 211,
          (byte) 19, (byte) 25, (byte) 138, (byte) 46, (byte) 3, (byte) 112, (byte) 115, (byte) 52
        };
    ret = Address.toByteArray("2001:0db8:0000:08d3:1319:8a2e:0370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    ret = Address.toByteArray("2001:0db8::08d3:1319:8a2e:0370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    exp =
        new byte[] {
          (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 133, (byte) 163, (byte) 8, (byte) 211,
          (byte) 19, (byte) 25, (byte) 138, (byte) 46, (byte) 3, (byte) 112, (byte) 115, (byte) 52
        };
    ret = Address.toByteArray("0000:0000:85a3:08d3:1319:8a2e:0370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);
    ret = Address.toByteArray("::85a3:08d3:1319:8a2e:0370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    exp =
        new byte[] {
          (byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 133, (byte) 163, (byte) 8, (byte) 211,
          (byte) 19, (byte) 25, (byte) 138, (byte) 46, (byte) 0, (byte) 0, (byte) 0, (byte) 0
        };
    ret = Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e:0:0", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    ret = Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e::", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    exp =
        new byte[] {
          (byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
          (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 3, (byte) 112, (byte) 115, (byte) 52
        };
    ret = Address.toByteArray("2001:0db8:0000:0000:0000:0000:0370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);
    ret = Address.toByteArray("2001:0db8:0:0:0:0:0370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);
    ret = Address.toByteArray("2001:0db8::0:0370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);
    ret = Address.toByteArray("2001:db8::370:7334", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    exp =
        new byte[] {
          (byte) 32,
          (byte) 1,
          (byte) 13,
          (byte) 184,
          (byte) 133,
          (byte) 163,
          (byte) 8,
          (byte) 211,
          (byte) 19,
          (byte) 25,
          (byte) 138,
          (byte) 46,
          (byte) 0xC0,
          (byte) 0xA8,
          (byte) 0x59,
          (byte) 0x09
        };
    ret = Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e:192.168.89.9", Address.IPv6);
    assertThat(ret).containsExactly(exp);

    exp =
        new byte[] {
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0,
          (byte) 0xC0,
          (byte) 0xA8,
          (byte) 0x59,
          (byte) 0x09
        };
    ret = Address.toByteArray("::192.168.89.9", Address.IPv6);
    assertThat(ret).containsExactly(exp);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        // not enough groups
        "2001:0db8:85a3:08d3:1319:8a2e:0370",
        // too many groups
        "2001:0db8:85a3:08d3:1319:8a2e:0370:193A:BCdE",
        // invalid letter
        "2001:0gb8:85a3:08d3:1319:8a2e:0370:9819",
        "lmno:0bb8:85a3:08d3:1319:8a2e:0370:9819",
        "11ab:0ab8:85a3:08d3:1319:8a2e:0370:qrst",
        // three consecutive colons
        "11ab:0ab8:85a3:08d3:::",
        // IPv4 in the middle
        "2001:0ab8:192.168.0.1:1319:8a2e:0370:9819",
        // invalid IPv4
        "2001:0ab8:1212:AbAb:8a2e:345.12.22.1",
        // group with too many digits
        "2001:0ab8:85a3:128d3:1319:8a2e:0370:9819",
      })
  void toByteArray_IPv6_invalid(String address) {
    assertThat(Address.toByteArray(address, Address.IPv6)).isNull();
  }

  @Test
  void toArray() {
    int[] exp = {1, 2, 3, 4};
    int[] ret = Address.toArray("1.2.3.4", Address.IPv4);
    assertThat(ret).containsExactly(exp);

    exp = new int[] {0, 0, 0, 0};
    ret = Address.toArray("0.0.0.0", Address.IPv4);
    assertThat(ret).containsExactly(exp);

    exp = new int[] {255, 255, 255, 255};
    ret = Address.toArray("255.255.255.255", Address.IPv4);
    assertThat(ret).containsExactly(exp);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "128.121.1",
        "",
      })
  void toArray_invalid(String address) {
    assertThat(Address.toArray(address, Address.IPv4)).isNull();
  }

  @Test
  void isDottedQuad() {
    assertThat(Address.isDottedQuad("1.2.3.4")).isTrue();
    assertThat(Address.isDottedQuad("256.2.3.4")).isFalse();
  }

  @Test
  void toDottedQuad() {
    assertThat(Address.toDottedQuad(new byte[] {(byte) 128, (byte) 176, (byte) 201, (byte) 1}))
        .isEqualTo("128.176.201.1");

    assertThat(Address.toDottedQuad(new int[] {200, 1, 255, 128})).isEqualTo("200.1.255.128");
  }

  @Test
  void addressLength() {
    assertThat(Address.addressLength(Address.IPv4)).isEqualTo(4);
    assertThat(Address.addressLength(Address.IPv6)).isEqualTo(16);

    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> Address.addressLength(3));
  }

  @Test
  void getByName() throws IOException {
    InetAddress out = Address.getByName("128.145.198.231");
    assertThat(out.getHostAddress()).isEqualTo("128.145.198.231");

    Name aRootServer = Name.fromString("a.root-servers.net.");
    Message aMessage = new Message();
    aMessage.getHeader().setRcode(Rcode.NOERROR);
    aMessage.addRecord(Record.newRecord(aRootServer, Type.A, DClass.IN), Section.QUESTION);
    aMessage.addRecord(
        new ARecord(
            aRootServer,
            DClass.IN,
            60,
            InetAddress.getByAddress(new byte[] {(byte) 198, 41, 0, 4})),
        Section.ANSWER);

    Resolver mockResolver = mock(Resolver.class);
    when(mockResolver.send(ArgumentMatchers.any(Message.class)))
        .thenAnswer(
            (Answer<Message>)
                invocation -> {
                  Message query = invocation.getArgument(0);
                  Message answer = aMessage.clone();
                  answer.addRecord(query.getQuestion(), Section.QUESTION);
                  return answer;
                });
    Lookup.setDefaultResolver(mockResolver);

    out = Address.getByName("a.root-servers.net");
    assertThat(out.getHostAddress()).isEqualTo("198.41.0.4");

    // reset resolver
    Lookup.refreshDefault();
  }

  @Test
  void getByName_invalid() throws IOException {
    Message m = new Message();
    m.getHeader().setRcode(Rcode.NXDOMAIN);
    Resolver mockResolver = mock(Resolver.class);
    when(mockResolver.send(ArgumentMatchers.any(Message.class)))
        .thenAnswer(
            (Answer<Message>)
                invocation -> {
                  Message query = invocation.getArgument(0);
                  Message answer = m.clone();
                  answer.addRecord(query.getQuestion(), Section.QUESTION);
                  return answer;
                });
    Lookup.setDefaultResolver(mockResolver);
    assertThatExceptionOfType(UnknownHostException.class)
        .isThrownBy(() -> Address.getByName("example.invalid"));
    // reset resolver
    Lookup.refreshDefault();

    assertThatExceptionOfType(UnknownHostException.class).isThrownBy(() -> Address.getByName(""));
  }

  @Test
  void getAllByName() throws IOException {
    InetAddress[] out = Address.getAllByName("128.145.198.231");
    assertThat(out.length).isOne();
    assertThat(out[0].getHostAddress()).isEqualTo("128.145.198.231");

    Name aRootServer = Name.fromString("a.root-servers.net.");
    Message aMessage = new Message();
    aMessage.getHeader().setRcode(Rcode.NOERROR);
    aMessage.addRecord(Record.newRecord(aRootServer, Type.A, DClass.IN), Section.QUESTION);
    aMessage.addRecord(
        new ARecord(
            aRootServer,
            DClass.IN,
            60,
            InetAddress.getByAddress(new byte[] {(byte) 198, 41, 0, 4})),
        Section.ANSWER);
    Message aaaaMessage = new Message();
    aaaaMessage.getHeader().setRcode(Rcode.NOERROR);
    aaaaMessage.addRecord(Record.newRecord(aRootServer, Type.AAAA, DClass.IN), Section.QUESTION);
    aaaaMessage.addRecord(
        new AAAARecord(
            aRootServer,
            DClass.IN,
            60,
            InetAddress.getByAddress(
                new byte[] {0x20, 1, 5, 3, (byte) 0xba, 0x3e, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x30})),
        Section.ANSWER);
    Resolver mockResolver = mock(Resolver.class);
    doReturn(aMessage)
        .when(mockResolver)
        .send(argThat(message -> message.getQuestion().getType() == Type.A));
    doReturn(aaaaMessage)
        .when(mockResolver)
        .send(argThat(message -> message.getQuestion().getType() == Type.AAAA));
    Lookup.setDefaultResolver(mockResolver);

    out = Address.getAllByName("a.root-servers.net");
    assertThat(out).hasSize(2);
    assertThat(out[0].getHostAddress()).isEqualTo("198.41.0.4");
    assertThat(out[1].getHostAddress()).isEqualTo("2001:503:ba3e:0:0:0:2:30");

    // reset resolver
    Lookup.refreshDefault();
  }

  @Test
  void getAllByName_invalid() throws IOException {
    Message m = new Message();
    m.getHeader().setRcode(Rcode.NXDOMAIN);
    Resolver mockResolver = mock(Resolver.class);
    when(mockResolver.send(ArgumentMatchers.any(Message.class)))
        .thenAnswer(
            (Answer<Message>)
                invocation -> {
                  Message query = invocation.getArgument(0);
                  Message answer = m.clone();
                  answer.addRecord(query.getQuestion(), Section.QUESTION);
                  return answer;
                });
    Lookup.setDefaultResolver(mockResolver);
    assertThatExceptionOfType(UnknownHostException.class)
        .isThrownBy(() -> Address.getAllByName("example.invalid"));

    // reset resolver
    Lookup.refreshDefault();

    assertThatExceptionOfType(UnknownHostException.class)
        .isThrownBy(() -> Address.getAllByName(""));
  }

  @Test
  void familyOf() throws UnknownHostException {
    assertThat(Address.familyOf(InetAddress.getByName("192.168.0.1"))).isEqualTo(Address.IPv4);
    assertThat(Address.familyOf(InetAddress.getByName("1:2:3:4:5:6:7:8"))).isEqualTo(Address.IPv6);
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> Address.familyOf(null));
  }

  @Test
  void getHostName() throws IOException {
    Name aRootServer = Name.fromString("a.root-servers.net.");
    Name aRootServerPtr = Name.fromString("4.0.41.198.in-addr.arpa.");
    Message ptrMessage = new Message();
    ptrMessage.getHeader().setRcode(Rcode.NOERROR);
    ptrMessage.addRecord(Record.newRecord(aRootServerPtr, Type.PTR, DClass.IN), Section.QUESTION);
    ptrMessage.addRecord(new PTRRecord(aRootServerPtr, DClass.IN, 60, aRootServer), Section.ANSWER);
    Resolver mockResolver = mock(Resolver.class);
    when(mockResolver.send(any(Message.class)))
        .thenAnswer(
            (Answer<Message>)
                invocation -> {
                  Message query = invocation.getArgument(0);
                  Message answer = ptrMessage.clone();
                  answer.addRecord(query.getQuestion(), Section.QUESTION);
                  return answer;
                });
    Lookup.setDefaultResolver(mockResolver);

    String out = Address.getHostName(InetAddress.getByName("198.41.0.4"));
    assertThat(out).isEqualTo("a.root-servers.net.");

    Message ptrMessage2 = new Message();
    ptrMessage.getHeader().setRcode(Rcode.NXDOMAIN);
    ptrMessage.addRecord(
        Record.newRecord(Name.fromString("1.1.168.192.in-addr.arpa."), Type.PTR, DClass.IN),
        Section.QUESTION);
    mockResolver = mock(Resolver.class);
    when(mockResolver.send(any()))
        .thenAnswer(
            (Answer<Message>)
                invocation -> {
                  Message query = invocation.getArgument(0);
                  Message answer = ptrMessage2.clone();
                  answer.addRecord(query.getQuestion(), Section.QUESTION);
                  return answer;
                });
    Lookup.setDefaultResolver(mockResolver);
    InetAddress address = InetAddress.getByName("192.168.1.1");
    assertThatExceptionOfType(UnknownHostException.class)
        .isThrownBy(() -> Address.getHostName(address));

    // reset resolver
    Lookup.refreshDefault();
  }
}
