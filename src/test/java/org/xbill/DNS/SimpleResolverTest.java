// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.io.IoClientFactory;
import org.xbill.DNS.io.TcpIoClient;
import org.xbill.DNS.io.UdpIoClient;

class SimpleResolverTest {
  private final Message query =
      Message.newQuery(
          Record.newRecord(Name.fromConstantString("example.com."), Type.TXT, DClass.IN));
  private final AtomicInteger tcpCalls = new AtomicInteger();
  private byte[] udpResponse;

  private SimpleResolver resolver() {
    SimpleResolver resolver = new SimpleResolver(new InetSocketAddress("127.0.0.1", 53));
    resolver.setIoClientFactory(
        new IoClientFactory() {
          @Override
          public TcpIoClient createOrGetTcpClient() {
            return (local, remote, request, data, timeout) -> {
              tcpCalls.incrementAndGet();
              return CompletableFuture.completedFuture(responseOfLength(142));
            };
          }

          @Override
          public UdpIoClient createOrGetUdpClient() {
            return (local, remote, request, data, max, timeout) ->
                CompletableFuture.completedFuture(
                    Arrays.copyOf(udpResponse, Math.min(max, udpResponse.length)));
          }
        });
    return resolver;
  }

  private byte[] responseOfLength(int length) {
    Message response = new Message(query.getHeader().getID());
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(query.getQuestion(), Section.QUESTION);
    // A compressed answer owner plus type, class, TTL and RDLENGTH uses 12 bytes.
    int remaining = length - response.toWire().length - 12;
    List<String> strings = new ArrayList<>();
    while (remaining > 0) {
      char[] value = new char[Math.min(255, remaining - 1)];
      Arrays.fill(value, 'x');
      strings.add(new String(value));
      remaining -= value.length + 1;
    }
    response.addRecord(
        new TXTRecord(query.getQuestion().getName(), DClass.IN, 60, strings), Section.ANSWER);
    byte[] wire = response.toWire();
    assertThat(wire).hasSize(length);
    return wire;
  }

  @ParameterizedTest
  @ValueSource(ints = {142, 1280, 1281, 2741})
  void oversizedUdpResponseRetriesOverTcp(int length) throws IOException {
    udpResponse = responseOfLength(length);

    Message response = resolver().send(query);

    assertThat(response.getSection(Section.ANSWER)).hasSize(1);
    assertThat(tcpCalls).hasValue(length > SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE ? 1 : 0);
  }

  @Test
  void ignoreTruncationDoesNotRetryOversizedUdpResponse() {
    udpResponse = responseOfLength(2741);
    SimpleResolver resolver = resolver();
    resolver.setIgnoreTruncation(true);

    assertThatThrownBy(() -> resolver.send(query)).isInstanceOf(WireParseException.class);
    assertThat(tcpCalls).hasValue(0);
  }

  @Test
  void malformedUdpResponseDoesNotRetryOverTcp() {
    udpResponse = Arrays.copyOf(responseOfLength(142), 141);

    assertThatThrownBy(() -> resolver().send(query)).isInstanceOf(WireParseException.class);
    assertThat(tcpCalls).hasValue(0);
  }

  @Test
  void oversizedUdpResponseWithWrongIdDoesNotRetryOverTcp() {
    udpResponse = responseOfLength(2741);
    udpResponse[0] ^= 1;

    assertThatThrownBy(() -> resolver().send(query))
        .isInstanceOf(WireParseException.class)
        .hasMessageStartingWith("invalid message id");
    assertThat(tcpCalls).hasValue(0);
  }

  @Test
  void udpResponseWithTcRetriesOverTcp() throws IOException {
    udpResponse = responseOfLength(142);
    udpResponse[2] |= 0x02;

    Message response = resolver().send(query);

    assertThat(response.getHeader().getFlag(Flags.TC)).isFalse();
    assertThat(tcpCalls).hasValue(1);
  }
}
