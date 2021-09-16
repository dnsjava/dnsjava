// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
final class AsyncSemaphore {
  private final Queue<CompletableFuture<Permit>> queue = new ArrayDeque<>();
  private final Permit singletonPermit = new Permit();
  private volatile int permits;

  private static class TimeoutCompletableFuture<T> extends CompletableFuture<T> {
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

    @SuppressWarnings("unchecked")
    public CompletableFuture<T> compatTimeout(long timeout, TimeUnit unit) {
      if (orTimeoutMethod == null) {
        return orTimeout(this, timeout, unit);
      } else {
        try {
          return (CompletableFuture<T>) orTimeoutMethod.invoke(this, timeout, unit);
        } catch (IllegalAccessException | InvocationTargetException e) {
          return orTimeout(this, timeout, unit);
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
          (r, ex) -> {
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

  final class Permit {
    public void release() {
      synchronized (queue) {
        CompletableFuture<Permit> next = queue.poll();
        if (next == null) {
          permits++;
        } else {
          next.complete(this);
        }
      }
    }
  }

  AsyncSemaphore(int permits) {
    this.permits = permits;
  }

  CompletionStage<Permit> acquire(Duration timeout) {
    synchronized (queue) {
      if (permits > 0) {
        permits--;
        return CompletableFuture.completedFuture(singletonPermit);
      } else {
        TimeoutCompletableFuture<Permit> f = new TimeoutCompletableFuture<>();
        f.compatTimeout(timeout.toNanos(), TimeUnit.NANOSECONDS)
            .whenComplete((result, ex) -> queue.remove(f));
        queue.add(f);
        return f;
      }
    }
  }
}
