// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.Test;

class DohResolverCommonTest {

  private static class TestDohResolver extends DohResolverCommon {
    protected TestDohResolver(String uriTemplate, int maxConcurrentRequests) {
      super(uriTemplate, maxConcurrentRequests);
    }

    @Override
    public CompletionStage<Message> sendAsync(Message query) {
      return null;
    }

    @Override
    protected <T> CompletableFuture<T> failedFuture(Throwable e) {
      CompletableFuture<T> f = new CompletableFuture<>();
      f.completeExceptionally(e);
      return f;
    }
  }

  @Test
  void testConstructor() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    assertThat(resolver.getUriTemplate()).isEqualTo("https://dns.google/dns-query");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TestDohResolver("https://dns.google/dns-query", 0));
  }

  @Test
  void testMaxConcurrentRequestsConfig() {
    String previousMaxConnections = System.getProperty("http.maxConnections");
    Executor executor = Runnable::run;
    try {
      System.setProperty("http.maxConnections", "2");
      TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);

      CompletionStage<AsyncSemaphore.Permit> first =
          resolver.maxConcurrentRequests.acquire(Duration.ofSeconds(1), 1, executor);
      CompletionStage<AsyncSemaphore.Permit> second =
          resolver.maxConcurrentRequests.acquire(Duration.ofSeconds(1), 2, executor);
      CompletionStage<AsyncSemaphore.Permit> third =
          resolver.maxConcurrentRequests.acquire(Duration.ofSeconds(1), 3, executor);

      assertThat(first.toCompletableFuture().isDone()).isTrue();
      assertThat(second.toCompletableFuture().isDone()).isTrue();
      assertThat(third.toCompletableFuture().isDone()).isFalse();

      first.toCompletableFuture().join().release(1, executor);
      assertThat(third.toCompletableFuture().isDone()).isTrue();
      second.toCompletableFuture().join().release(2, executor);
    } finally {
      if (previousMaxConnections == null) {
        System.clearProperty("http.maxConnections");
      } else {
        System.setProperty("http.maxConnections", previousMaxConnections);
      }
    }
  }

  @Test
  void testGetSetUriTemplate() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    resolver.setUriTemplate("https://cloudflare-dns.com/dns-query");
    assertThat(resolver.getUriTemplate()).isEqualTo("https://cloudflare-dns.com/dns-query");
  }

  @Test
  void testGetSetTimeout() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    assertThat(resolver.getTimeout()).isEqualTo(Duration.ofSeconds(5));
    resolver.setTimeout(Duration.ofSeconds(10));
    assertThat(resolver.getTimeout()).isEqualTo(Duration.ofSeconds(10));
  }

  @Test
  void testGetSetUsePost() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    assertThat(resolver.isUsePost()).isFalse();
    resolver.setUsePost(true);
    assertThat(resolver.isUsePost()).isTrue();
  }

  @Test
  void testGetUrl() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    byte[] queryBytes = {1, 2, 3};
    String url = resolver.getUrl(queryBytes);
    assertThat(url).contains("dns=");

    resolver.setUsePost(true);
    url = resolver.getUrl(queryBytes);
    assertThat(url).isEqualTo("https://dns.google/dns-query");
  }

  @Test
  void testPrepareQuery() throws TextParseException {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    Message query = new Message();
    query.getHeader().setID(1234);
    query.addRecord(
        Record.newRecord(Name.fromString("example.com."), Type.A, DClass.IN), Section.QUESTION);

    Message prepared = resolver.prepareQuery(query);
    assertThat(prepared.getHeader().getID()).isZero();
    assertThat(prepared.getOPT()).isNotNull(); // Default OPT added

    resolver.setEDNS(-1, 0, 0, Collections.emptyList());
    prepared = resolver.prepareQuery(query);
    assertThat(prepared.getOPT()).isNull();
  }

  @Test
  void testSetEDNS() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    resolver.setEDNS(0, 1232, Flags.DO, Collections.emptyList());
    Message query = new Message();
    Message prepared = resolver.prepareQuery(query);
    assertThat(prepared.getOPT()).isNotNull();
    assertThat(prepared.getOPT().getVersion()).isZero();
    assertThat(prepared.getOPT().getFlags() & Flags.DO).isEqualTo(Flags.DO);
    assertThat(prepared.getOPT().getFlags()).isEqualTo(Flags.DO);
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> resolver.setEDNS(1, 0, 0, Collections.emptyList()));
  }

  @Test
  void testSetTSIGKey() throws TextParseException {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    TSIG key = new TSIG(TSIG.HMAC_SHA256, "keyname.", "YmFzZTY0ZGF0YQ==");
    resolver.setTSIGKey(key);
    Message query = new Message();
    query.addRecord(
        Record.newRecord(Name.fromString("example.com."), Type.A, DClass.IN), Section.QUESTION);
    Message prepared = resolver.prepareQuery(query);
    assertThat(prepared.getTSIG()).isNotNull();
  }

  @Test
  void testNoOps() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    assertThatCode(() -> resolver.setPort(853)).doesNotThrowAnyException();
    assertThatCode(() -> resolver.setTCP(true)).doesNotThrowAnyException();
    assertThatCode(() -> resolver.setIgnoreTruncation(true)).doesNotThrowAnyException();
  }

  @Test
  void testToString() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    assertThat(resolver).hasToString("DohResolver {GET https://dns.google/dns-query}");
    resolver.setUsePost(true);
    assertThat(resolver).hasToString("DohResolver {POST https://dns.google/dns-query}");
  }

  @Test
  void testVerifyTSIG() throws TextParseException {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    TSIG key = new TSIG(TSIG.HMAC_SHA256, "keyname.", "YmFzZTY0ZGF0YQ==");

    Message query = new Message();
    query.addRecord(
        Record.newRecord(Name.fromString("example.com."), Type.A, DClass.IN), Section.QUESTION);
    query.setTSIG(key, Rcode.NOERROR, null);

    Message response = new Message();
    response.getHeader().setID(query.getHeader().getID());
    response.addRecord(query.getQuestion(), Section.QUESTION);
    response.setTSIG(key, Rcode.NOERROR, query.getTSIG());

    assertThatCode(() -> resolver.verifyTSIG(query, response, response.toWire(), key))
        .doesNotThrowAnyException();
  }

  @Test
  void testFailedFuture() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    Exception ex = new Exception("test");
    CompletableFuture<Object> f = resolver.failedFuture(ex);
    assertThat(f.isCompletedExceptionally()).isTrue();
  }

  @Test
  void testTimeoutFailedFuture() throws TextParseException {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    Message query = new Message();
    query.addRecord(
        Record.newRecord(Name.fromString("example.com."), Type.A, DClass.IN), Section.QUESTION);

    CompletableFuture<Object> f = resolver.timeoutFailedFuture(query, new Exception("inner"));
    assertThat(f.isCompletedExceptionally()).isTrue();

    f = resolver.timeoutFailedFuture(query, "extra message", new Exception("inner"));
    assertThat(f.isCompletedExceptionally()).isTrue();
  }
}
