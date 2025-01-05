// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.io.IoClientFactory;
import org.xbill.DNS.io.TcpIoClient;
import org.xbill.DNS.io.UdpIoClient;

class UpdateTest {
  private static final Name exampleCom = Name.fromConstantString("example.com.");

  private Update getLargeUpdateMessage() throws TextParseException {
    Update u = new Update(exampleCom);
    for (int i = 0; i < 2000; i++) {
      u.add(
          new TXTRecord(
              new Name("name-" + i, exampleCom), DClass.IN, 900, UUID.randomUUID().toString()));
    }
    return u;
  }

  @Test
  void toWireThrowsOnDisallowedTruncation() throws IOException {
    Update u = getLargeUpdateMessage();
    assertThatThrownBy(() -> u.toWire(Message.MAXLENGTH, false))
        .isInstanceOf(MessageSizeExceededException.class);
  }

  @Test
  void toWireAllowsTruncationByDefault() throws IOException, MessageSizeExceededException {
    Update u = getLargeUpdateMessage();
    int maxSize = 16384;
    byte[] defaultOverloadResult = u.toWire(maxSize);
    byte[] truncationAllowedResult = u.toWire(maxSize, true);
    Message readBack = new Message(defaultOverloadResult);
    assertThat(defaultOverloadResult).isEqualTo(truncationAllowedResult).hasSizeLessThan(maxSize);
    assertThat(readBack.getHeader().getFlag(Flags.TC)).isTrue();
  }

  @Test
  void resolverForbidsTruncation() throws TextParseException, UnknownHostException {
    Update u = getLargeUpdateMessage();
    SimpleResolver r = new SimpleResolver("127.0.0.1");
    r.setIoClientFactory(
        new IoClientFactory() {
          @Override
          public TcpIoClient createOrGetTcpClient() {
            return (local, remote, query, data, timeout) -> CompletableFuture.completedFuture(data);
          }

          @Override
          public UdpIoClient createOrGetUdpClient() {
            throw new RuntimeException("Not implemented");
          }
        });
    r.setTCP(true);
    assertThatThrownBy(() -> r.send(u))
        .rootCause()
        .isInstanceOf(MessageSizeExceededException.class);
  }
}
