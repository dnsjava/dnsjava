// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;

@Slf4j
final class AsyncSemaphore {
  private final Queue<CompletableFuture<Permit>> queue = new ArrayDeque<>();
  private final Permit singletonPermit = new Permit();
  private volatile int permits;

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
