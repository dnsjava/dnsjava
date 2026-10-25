// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.io.IoClientFactory;
import org.xbill.DNS.io.TcpIoClient;
import org.xbill.DNS.io.UdpIoClient;

class SimpleResolverDeniedTest {

  @Test
  void emptyResponseShouldThrowWireParseException() throws IOException {

    Name zone = Name.fromString("example.");
    Message query = Message.newUpdate(zone);
    Record cnameRecord =
        new CNAMERecord(Name.fromString("www", zone), DClass.IN, 300, Name.fromString("example."));
    query.addRecord(cnameRecord, Section.UPDATE);

    SimpleResolver simpleResolver = new SimpleResolver("127.0.0.1");
    simpleResolver.setIoClientFactory(
        new IoClientFactory() {
          @Override
          public TcpIoClient createOrGetTcpClient() {
            return null;
          }

          @Override
          public UdpIoClient createOrGetUdpClient() {
            UdpIoClient udpMock = mock(NioUdpClient.class);
            when(udpMock.sendAndReceiveUdp(
                    any(),
                    any(InetSocketAddress.class),
                    any(Message.class),
                    any(byte[].class),
                    anyInt(),
                    any(Duration.class)))
                .thenAnswer(
                    a -> {
                      Message qparsed = new Message(a.<byte[]>getArgument(3));

                      int id = qparsed.getHeader().getID();
                      Message response = new Message(id);
                      response.getHeader().setRcode(Rcode.REFUSED);
                      byte[] rbytes = response.toWire(Message.MAXLENGTH);

                      // This was the exact format returned by denying server
                      assertThat(
                              new byte[] {
                                (byte) (id >>> 8), (byte) id, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0
                              })
                          .containsExactly(rbytes);

                      CompletableFuture<byte[]> f = new CompletableFuture<>();
                      f.complete(rbytes);
                      return f;
                    });
            return udpMock;
          }
        });

    assertThatExceptionOfType(WireParseException.class)
        .isThrownBy(() -> simpleResolver.send(query));
  }
}
