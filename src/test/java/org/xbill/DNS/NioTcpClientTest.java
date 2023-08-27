// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.utils.base16;

class NioTcpClientTest {
  private static final String SELECTOR_TIMEOUT_PROPERTY = "dnsjava.nio.selector_timeout";

  @ParameterizedTest
  @ValueSource(ints = {0, 1001})
  void testSelectorTimeoutLimits(int timeout) {
    System.setProperty(SELECTOR_TIMEOUT_PROPERTY, Integer.toString(timeout));
    try {
      assertThrows(IllegalArgumentException.class, NioClient::runSelector);
    } finally {
      System.clearProperty(SELECTOR_TIMEOUT_PROPERTY);
    }
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
      try (ServerSocket ss = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
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
                        Message serverReceivedMessage = new Message(messageData);

                        for (int j = q.length - 1; j >= 0; j--) {
                          Message answer = new Message();
                          answer.getHeader().setRcode(Rcode.NOERROR);
                          answer.getHeader().setID(serverReceivedMessage.getHeader().getID());
                          answer.addRecord(serverReceivedMessage.getQuestion(), Section.QUESTION);
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
      }
    } finally {
      NioClient.close();
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"000101", "0000", "0002", "000201"})
  void testTooShortResponseStream(String base16ResponseBytes)
      throws InterruptedException, IOException {
    byte[] responseBytes = base16.fromString(base16ResponseBytes);
    try {
      // start the selector thread early
      NioClient.selector();

      Record qr = Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN);
      Message q = Message.newQuery(qr);
      CountDownLatch cdlServerThreadStart = new CountDownLatch(1);
      CountDownLatch cdlWaitForResult = new CountDownLatch(1);
      try (ServerSocket ss = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
        ss.setSoTimeout(5000);
        Thread server =
            new Thread(
                () -> {
                  try {
                    cdlServerThreadStart.countDown();
                    Socket s = ss.accept();
                    try {
                      InputStream is = s.getInputStream();
                      byte[] lengthData = new byte[2];
                      int readLength = is.read(lengthData);
                      assertEquals(2, readLength);
                      byte[] messageData = new byte[(lengthData[0] << 8) + lengthData[1]];
                      int readMessageLength = is.read(messageData);
                      assertEquals(messageData.length, readMessageLength);

                      // Send an invalid response, too short to contain an ID
                      OutputStream os = s.getOutputStream();
                      os.write(responseBytes);
                      os.flush();
                    } catch (IOException e) {
                      fail(e);
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

        NioTcpClient.sendrecv(
                null,
                (InetSocketAddress) ss.getLocalSocketAddress(),
                q,
                q.toWire(),
                Duration.ofSeconds(1))
            .whenComplete(
                (r, e) -> {
                  cdlWaitForResult.countDown();
                  if (e == null) {
                    fail("Got an answer but expected timeout");
                  }
                });

        if (!cdlWaitForResult.await(5, TimeUnit.SECONDS)) {
          fail("Timeout");
        }
      }
    } finally {
      NioClient.close();
    }
  }
}
