// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import io.vertx.core.Vertx;
import io.vertx.core.datagram.DatagramSocket;
import io.vertx.core.net.SocketAddress;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

@ExtendWith(VertxExtension.class)
@SuppressWarnings("unchecked")
class NioUdpClientTest {
  private static SocketAddress localAddress;

  @BeforeAll
  static void beforeAll(Vertx vertx, VertxTestContext context) {
    DatagramSocket datagramSocket = vertx.createDatagramSocket();
    datagramSocket.handler(
        p -> datagramSocket.send(p.data(), p.sender().port(), p.sender().host()));
    datagramSocket
        .listen(0, "localhost")
        .map(
            s -> {
              localAddress = s.localAddress();
              return null;
            })
        .onComplete(context.succeedingThenComplete());
  }

  @AfterAll
  static void afterAll() {
    NioClient.close();
  }

  private CompletableFuture<byte[]> createAndSendQuery() {
    NioUdpClient udp = new NioUdpClient();
    Message query = Message.newQuery(Record.newRecord(Name.root, Type.A, DClass.IN));
    return udp.sendAndReceiveUdp(
        null,
        new InetSocketAddress(localAddress.hostAddress(), localAddress.port()),
        query,
        query.toWire(),
        65535,
        Duration.ofSeconds(10));
  }

  @Test
  void selectorWithAllCanceledKey() throws IOException {
    Selector spiedSelector = spy(Selector.open());
    when(spiedSelector.selectedKeys())
        .thenAnswer(
            a -> {
              Set<SelectionKey> keys = (Set<SelectionKey>) a.callRealMethod();
              for (SelectionKey key : keys) {
                key.cancel();
              }
              return keys;
            });

    try (MockedStatic<Selector> sel = Mockito.mockStatic(Selector.class)) {
      sel.when(Selector::open).thenReturn(spiedSelector);
      CompletableFuture<byte[]> result = createAndSendQuery();
      assertThatThrownBy(result::get).hasCauseInstanceOf(EOFException.class);
    }
  }

  @Test
  void readFromKeyFailsFuture() throws IOException {
    Selector spiedSelector = spy(Selector.open());
    when(spiedSelector.selectedKeys())
        .thenAnswer(
            selectedKeysIntercept -> {
              Set<SelectionKey> keys = (Set<SelectionKey>) selectedKeysIntercept.callRealMethod();
              Set<SelectionKey> mockedKeys = new HashSet<>(keys.size());
              for (SelectionKey key : keys) {
                SelectionKey spy = spy(key);
                when(spy.channel())
                    .thenAnswer(
                        channelIntercept -> {
                          DatagramChannel channel =
                              (DatagramChannel) channelIntercept.callRealMethod();
                          DatagramChannel spyChannel = spy(channel);
                          doReturn(0).when(spyChannel).read(any(ByteBuffer.class));
                          return spyChannel;
                        });
                mockedKeys.add(spy);
              }

              return mockedKeys;
            });

    try (MockedStatic<Selector> sel = Mockito.mockStatic(Selector.class)) {
      sel.when(Selector::open).thenReturn(spiedSelector);
      CompletableFuture<byte[]> result = createAndSendQuery();
      assertThatThrownBy(result::get)
          .cause()
          .isInstanceOf(EOFException.class)
          .hasMessageStartingWith("Could not read expected data");
    }
  }
}
