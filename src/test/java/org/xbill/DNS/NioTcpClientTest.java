// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class NioTcpClientTest {
  @Test
  void testSelectorTimeoutUnder() throws IOException {
    System.setProperty("dnsjava.nio.selector_timeout", "0");
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          NioClient.runSelector();
        });
  }

  @Test
  void testSelectorTimeoutOver() throws IOException {
    System.setProperty("dnsjava.nio.selector_timeout", "1001");
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          NioClient.runSelector();
        });
  }

  @Test
  void testResponseStream() throws InterruptedException, IOException {
    try {
      // start the selector thread early
      NioClient.selector();

      Record qr = Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN);
      Message[] q = new Message[] {Message.newQuery(qr), Message.newQuery(qr)};
      CountDownLatch cdlServerThreadStart = new CountDownLatch(1);
      CountDownLatch cdlQueryRepliesReceived = new CountDownLatch(q.length);
      ServerSocket ss = new ServerSocket(0, 0, InetAddress.getLoopbackAddress());
      ss.setSoTimeout(5000);
      Thread server =
          new Thread(
              () -> {
                try {
                  cdlServerThreadStart.countDown();
                  Socket s = ss.accept();
                  for (int i = 0; i < q.length; i++) {
                    try {
                      InputStream is = s.getInputStream();
                      byte[] lengthData = new byte[2];
                      int readLength = is.read(lengthData);
                      assertEquals(2, readLength);
                      byte[] messageData = new byte[(lengthData[0] << 8) + lengthData[1]];
                      int readMessageLength = is.read(messageData);
                      assertEquals(messageData.length, readMessageLength);
                      Message serverReceivedMessages = new Message(messageData);

                      for (int j = q.length - 1; j >= 0; j--) {
                        Message answer = new Message();
                        answer.getHeader().setRcode(Rcode.NOERROR);
                        answer.getHeader().setID(serverReceivedMessages.getHeader().getID());
                        answer.addRecord(serverReceivedMessages.getQuestion(), Section.QUESTION);
                        answer.addRecord(
                            new ARecord(
                                Name.fromConstantString("example.com."),
                                DClass.IN,
                                900,
                                InetAddress.getLoopbackAddress()),
                            Section.ANSWER);
                        byte[] queryData = answer.toWire();
                        ByteBuffer buffer = ByteBuffer.allocate(queryData.length + 2);
                        buffer.put((byte) (queryData.length >>> 8));
                        buffer.put((byte) (queryData.length & 0xFF));
                        buffer.put(queryData);
                        s.getOutputStream().write(buffer.array());
                      }

                    } catch (IOException e) {
                      fail(e);
                    }
                  }
                } catch (SocketTimeoutException ste) {
                  fail("Timeout waiting for a client connection", ste);
                } catch (IOException e) {
                  fail(e);
                }
              });
      server.start();

      if (!cdlServerThreadStart.await(5, TimeUnit.SECONDS)) {
        fail("timed out waiting for server thread to start");
      }

      for (int j = 0; j < q.length; j++) {
        int jj = j;
        NioTcpClient.sendrecv(
                null,
                (InetSocketAddress) ss.getLocalSocketAddress(),
                q[j],
                q[j].toWire(),
                Duration.ofSeconds(5))
            .thenAccept(
                d -> {
                  try {
                    assertEquals(q[jj].getHeader().getID(), new Message(d).getHeader().getID());
                    cdlQueryRepliesReceived.countDown();
                  } catch (IOException e) {
                    fail(e);
                  }
                });
      }

      if (!cdlQueryRepliesReceived.await(5, TimeUnit.SECONDS)) {
        fail("timed out waiting for answers");
      }
    } finally {
      NioClient.close();
    }
  }
}
