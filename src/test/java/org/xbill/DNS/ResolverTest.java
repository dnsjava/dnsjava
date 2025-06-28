// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class ResolverTest {
  @Test
  @SuppressWarnings("deprecation")
  void resolverListenerExceptionUnwrap() throws InterruptedException, UnknownHostException {
    // 1. Point to a blackhole address from RFC 5737 TEST-NET-1 to ensure a timeout
    SimpleResolver resolver = new SimpleResolver("192.0.2.1");
    resolver.setTimeout(Duration.ofSeconds(2));

    Message query =
        Message.newQuery(
            Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN));
    CountDownLatch latch = new CountDownLatch(1);

    // 2. Use the async method with a listener
    resolver.sendAsync(
        query,
        new ResolverListener() {
          @Override
          public void receiveMessage(Object id, Message m) {
            fail("Received message (should not happen)");
            latch.countDown();
          }

          @Override
          public void handleException(Object id, Exception ex) {
            // 3. Observe the exception type
            assertThat(ex).isNotInstanceOf(CompletionException.class);
            latch.countDown();
          }
        });

    latch.await(5, TimeUnit.SECONDS);
  }
}
