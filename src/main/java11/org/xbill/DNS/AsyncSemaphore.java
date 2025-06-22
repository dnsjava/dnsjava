// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;

@Slf4j
final class AsyncSemaphore {
  private final Queue<CompletableFuture<Permit>> queue = new ArrayDeque<>();
  private final Permit singletonPermit = new Permit();
  private final String name;
  private volatile int permits;

  final class Permit {
    public void release(int id, Executor executor) {
      synchronized (queue) {
        CompletableFuture<Permit> next = queue.poll();
        if (next == null) {
          permits++;
          log.trace("{} permit released id={}, available={}", name, id, permits);
        } else {
          log.trace("{} permit released id={}, available={}, immediate next", name, id, permits);
          next.completeAsync(() -> this, executor);
        }
      }
    }
  }

  AsyncSemaphore(int permits, String name) {
    this.permits = permits;
    this.name = name;
    log.debug("Using Java 11+ implementation for {}", name);
  }

  CompletionStage<Permit> acquire(Duration timeout, int id, Executor executor) {
    synchronized (queue) {
      if (permits > 0) {
        permits--;
        log.trace("{} permit acquired id={}, available={}", name, id, permits);
        return CompletableFuture.completedFuture(singletonPermit);
      } else {
        CompletableFuture<Permit> f = new CompletableFuture<>();
        f.orTimeout(timeout.toNanos(), TimeUnit.NANOSECONDS)
            .whenCompleteAsync(
                (result, ex) -> {
                  synchronized (queue) {
                    if (ex != null) {
                      log.trace("{} permit timed out id={}, available={}", name, id, permits);
                    }
                    queue.remove(f);
                  }
                },
                executor);
        log.trace("{} permit queued id={}, available={}", name, id, permits);
        queue.add(f);
        return f;
      }
    }
  }
}
