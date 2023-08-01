// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class SimpleResolverDeniedTest {

  @Test
  void emptyResponseShouldThrowWireParseException() throws IOException {

    Name zone = Name.fromString("example.");
    Message query = Message.newUpdate(zone);
    Record record =
        new CNAMERecord(Name.fromString("www", zone), DClass.IN, 300, Name.fromString("example."));
    query.addRecord(record, Section.UPDATE);

    try (MockedStatic<NioUdpClient> udpClient = Mockito.mockStatic(NioUdpClient.class)) {
      udpClient
          .when(
              () ->
                  NioUdpClient.sendrecv(
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
                assertArrayEquals(
                    rbytes,
                    new byte[] {(byte) (id >>> 8), (byte) id, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0});

                CompletableFuture<byte[]> f = new CompletableFuture<>();
                f.complete(rbytes);
                return f;
              });

      SimpleResolver simpleResolver = new SimpleResolver("127.0.0.1");

      assertThrows(WireParseException.class, () -> simpleResolver.send(query));
    }
  }
}
