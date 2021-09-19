// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility class to backport {@code orTimeout} to Java 8 with a custom implementation. On Java 9+
 * the built-in method is called.
 */
@Slf4j
class TimeoutCompletableFuture<T> extends CompletableFuture<T> {
  private static final Method orTimeoutMethod;

  static {
    Method localOrTimeoutMethod;
    if (!System.getProperty("java.version").startsWith("1.")) {
      try {
        localOrTimeoutMethod =
            CompletableFuture.class.getMethod("orTimeout", long.class, TimeUnit.class);
      } catch (NoSuchMethodException e) {
        localOrTimeoutMethod = null;
        log.warn(
            "CompletableFuture.orTimeout method not found in Java 9+, using custom implementation",
            e);
      }
    } else {
      localOrTimeoutMethod = null;
    }
    orTimeoutMethod = localOrTimeoutMethod;
  }

  public CompletableFuture<T> compatTimeout(long timeout, TimeUnit unit) {
    return compatTimeout(this, timeout, unit);
  }

  @SuppressWarnings("unchecked")
  public static <T> CompletableFuture<T> compatTimeout(
      CompletableFuture<T> f, long timeout, TimeUnit unit) {
    if (orTimeoutMethod == null) {
      return orTimeout(f, timeout, unit);
    } else {
      try {
        return (CompletableFuture<T>) orTimeoutMethod.invoke(f, timeout, unit);
      } catch (IllegalAccessException | InvocationTargetException e) {
        return orTimeout(f, timeout, unit);
      }
    }
  }

  private static <T> CompletableFuture<T> orTimeout(
      CompletableFuture<T> f, long timeout, TimeUnit unit) {
    ScheduledFuture<?> sf =
        TimeoutScheduler.executor.schedule(
            () -> {
              if (!f.isDone()) {
                f.completeExceptionally(new TimeoutException());
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
