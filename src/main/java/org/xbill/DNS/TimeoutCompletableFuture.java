// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import lombok.extern.slf4j.Slf4j;

/** Utility class to backport {@code orTimeout} to Java 8 with a custom implementation. */
@Slf4j
class TimeoutCompletableFuture<T> extends CompletableFuture<T> {
  public CompletableFuture<T> compatTimeout(long timeout, TimeUnit unit) {
    return compatTimeout(this, timeout, unit);
  }

  public static <T> CompletableFuture<T> compatTimeout(
      CompletableFuture<T> f, long timeout, TimeUnit unit) {
    if (timeout <= 0) {
      f.completeExceptionally(new TimeoutException("timeout is " + timeout + ", but must be > 0"));
    }

    ScheduledFuture<?> sf =
        TimeoutScheduler.executor.schedule(
            () -> {
              if (!f.isDone()) {
                f.completeExceptionally(
                    new TimeoutException(
                        "Timeout of "
                            + unit.toMillis(timeout)
                            + "ms has elapsed before the task completed"));
              }
            },
            timeout,
            unit);
    f.whenComplete(
        (result, ex) -> {
          if (ex == null && !sf.isDone()) {
            sf.cancel(false);
          }
        });
    return f;
  }

  private static final class TimeoutScheduler {
    private static final ScheduledThreadPoolExecutor executor;

    static {
      executor =
          new ScheduledThreadPoolExecutor(
              1,
              r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                t.setName("dnsjava AsyncSemaphoreTimeoutScheduler");
                return t;
              });
      executor.setRemoveOnCancelPolicy(true);
    }
  }
}
