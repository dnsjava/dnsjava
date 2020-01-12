// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

public class NioTcpClientTest {
  @Test
  void testResponseStream() throws InterruptedException, IOException {
    Record qr = Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN);
    Message[] q = new Message[] {Message.newQuery(qr), Message.newQuery(qr)};
    CountDownLatch cdl1 = new CountDownLatch(q.length);
    CountDownLatch cdl2 = new CountDownLatch(q.length);
    Message[] serverReceivedMessages = new Message[q.length];
    Message[] clientReceivedAnswers = new Message[q.length];
    AtomicInteger i = new AtomicInteger(0);
    Socket[] s = new Socket[1];
    ServerSocket ss = new ServerSocket(0);
    Thread server =
        new Thread(
            () -> {
              try {
                s[0] = ss.accept();
                while (cdl1.getCount() > 0) {
                  int ii = i.getAndIncrement();
                  try {
                    InputStream is = s[0].getInputStream();
                    byte[] lengthData = new byte[2];
                    int readLength = is.read(lengthData);
                    assertEquals(2, readLength);
                    byte[] messageData = new byte[(lengthData[0] << 8) + lengthData[1]];
                    int readMessageLength = is.read(messageData);
                    assertEquals(messageData.length, readMessageLength);
                    serverReceivedMessages[ii] = new Message(messageData);
                    cdl1.countDown();
                  } catch (IOException e) {
                    fail(e);
                  }
                }
              } catch (IOException e) {
                fail(e);
              }
            });
    server.start();

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
                  clientReceivedAnswers[jj] = new Message(d);
                  cdl2.countDown();
                } catch (IOException e) {
                  fail(e);
                }
              });
    }

    if (!cdl1.await(5, TimeUnit.SECONDS)) {
      fail("timed out waiting for messages");
    }

    for (int j = q.length - 1; j >= 0; j--) {
      Message answer = new Message();
      answer.getHeader().setRcode(Rcode.NOERROR);
      answer.getHeader().setID(serverReceivedMessages[j].getHeader().getID());
      answer.addRecord(serverReceivedMessages[j].getQuestion(), Section.QUESTION);
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
      s[0].getOutputStream().write(buffer.array());
    }

    if (!cdl2.await(5, TimeUnit.SECONDS)) {
      fail("timed out waiting for answers");
    }

    for (int j = 0; j < q.length; j++) {
      assertEquals(q[j].getHeader().getID(), clientReceivedAnswers[j].getHeader().getID());
    }
  }
}
