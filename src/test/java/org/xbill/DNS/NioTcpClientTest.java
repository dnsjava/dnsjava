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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.opentest4j.AssertionFailedError;
import org.xbill.DNS.utils.base16;

@Slf4j
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
      CountDownLatch cdlServerThreadEnd = new CountDownLatch(1);
      CountDownLatch cdlQueryRepliesReceived = new CountDownLatch(q.length);
      List<Throwable> exceptions = new ArrayList<>();
      try (ServerSocket ss = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
        ss.setSoTimeout(15000);
        Thread server =
            new Thread(
                () -> {
                  try {
                    cdlServerThreadStart.countDown();
                    Socket s = ss.accept();
                    for (int i = 0; i < q.length; i++) {
                      log.debug("Sending reply #{}, id={}", i, q[i].getHeader().getID());
                      try {
                        InputStream is = s.getInputStream();
                        byte[] lengthData = new byte[2];
                        int readLength = is.read(lengthData);
                        assertEquals(2, readLength);
                        byte[] messageData = new byte[(lengthData[0] << 8) + lengthData[1]];
                        int readMessageLength = is.read(messageData);
                        assertEquals(messageData.length, readMessageLength);
                        Message serverReceivedMessage = new Message(messageData);

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
                        byte[] answerData = answer.toWire();
                        ByteBuffer answerBuffer = ByteBuffer.allocate(answerData.length + 2);
                        answerBuffer.put((byte) (answerData.length >>> 8));
                        answerBuffer.put((byte) (answerData.length & 0xFF));
                        answerBuffer.put(answerData);
                        s.getOutputStream().write(answerBuffer.array());

                      } catch (IOException e) {
                        log.warn("Writing message to client failed", e);
                        exceptions.add(e);
                      }
                    }
                  } catch (IOException e) {
                    log.warn("Server failed", e);
                    exceptions.add(e);
                  }

                  cdlServerThreadEnd.countDown();
                });
        server.setDaemon(true);
        server.start();

        if (!cdlServerThreadStart.await(15, TimeUnit.SECONDS)) {
          fail("timed out waiting for server thread to start");
        }

        for (int j = 0; j < q.length; j++) {
          int jj = j;
          NioTcpClient.sendrecv(
                  null,
                  (InetSocketAddress) ss.getLocalSocketAddress(),
                  q[j],
                  q[j].toWire(),
                  Duration.ofSeconds(15))
              .whenComplete(
                  (d, e1) -> {
                    if (e1 == null) {
                      try {
                        assertEquals(q[jj].getHeader().getID(), new Message(d).getHeader().getID());
                      } catch (IOException | AssertionFailedError e2) {
                        exceptions.add(e2);
                      }
                    } else {
                      log.warn("sendrcv failed", e1);
                      exceptions.add(e1);
                    }
                    cdlQueryRepliesReceived.countDown();
                  });
        }

        if (!cdlQueryRepliesReceived.await(15, TimeUnit.SECONDS)) {
          fail("timed out waiting for answers in client");
        }

        if (!cdlServerThreadEnd.await(15, TimeUnit.SECONDS)) {
          fail("timeout waiting for server to stop");
        }
      }

      for (Throwable t : exceptions) {
        log.error("Failure during test run", t);
      }
      assertEquals(0, exceptions.size(), "Test had exceptions in async code");
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
      CountDownLatch cdlServerThreadEnd = new CountDownLatch(1);
      CountDownLatch cdlWaitForResult = new CountDownLatch(1);
      List<Throwable> exceptions = new ArrayList<>();
      try (ServerSocket ss = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
        ss.setSoTimeout(15000);
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
                    log.warn("Timeout waiting for a client connection", ste);
                    exceptions.add(ste);
                  } catch (IOException e) {
                    log.warn("Server failed", e);
                    exceptions.add(e);
                  }

                  cdlServerThreadEnd.countDown();
                });
        server.setDaemon(true);
        server.start();

        if (!cdlServerThreadStart.await(15, TimeUnit.SECONDS)) {
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
                    exceptions.add(new AssertionError("Got an answer but expected timeout"));
                  }
                });

        if (!cdlWaitForResult.await(15, TimeUnit.SECONDS)) {
          fail("Timeout");
        }

        if (!cdlServerThreadEnd.await(15, TimeUnit.SECONDS)) {
          fail("timeout waiting for server to stop");
        }
      }

      for (Throwable t : exceptions) {
        log.error("Failure during test run", t);
      }
      assertEquals(0, exceptions.size(), "Test had exceptions in async code");
    } finally {
      NioClient.close();
    }
  }
}
