package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class DohResolverCommonTest {

  private static class TestDohResolver extends DohResolverCommon {
    protected TestDohResolver(String uriTemplate, int maxConcurrentRequests) {
      super(uriTemplate, maxConcurrentRequests);
    }

    @Override
    public java.util.concurrent.CompletionStage<Message> sendAsync(Message query) {
      return null;
    }

    @Override
    protected <T> java.util.concurrent.CompletableFuture<T> failedFuture(Throwable e) {
      java.util.concurrent.CompletableFuture<T> f = new java.util.concurrent.CompletableFuture<>();
      f.completeExceptionally(e);
      return f;
    }
  }

  @Test
  void testConstructor() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    assertEquals("https://dns.google/dns-query", resolver.getUriTemplate());
    assertThrows(IllegalArgumentException.class, () -> new TestDohResolver("https://dns.google/dns-query", 0));
  }

  @Test
  void testGetSetUriTemplate() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    resolver.setUriTemplate("https://cloudflare-dns.com/dns-query");
    assertEquals("https://cloudflare-dns.com/dns-query", resolver.getUriTemplate());
  }

  @Test
  void testGetSetTimeout() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    assertEquals(Duration.ofSeconds(5), resolver.getTimeout());
    resolver.setTimeout(Duration.ofSeconds(10));
    assertEquals(Duration.ofSeconds(10), resolver.getTimeout());
  }

  @Test
  void testGetSetUsePost() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    assertFalse(resolver.isUsePost());
    resolver.setUsePost(true);
    assertTrue(resolver.isUsePost());
  }

  @Test
  void testGetUrl() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    byte[] queryBytes = new byte[] {1, 2, 3};
    String url = resolver.getUrl(queryBytes);
    assertTrue(url.contains("dns="));

    resolver.setUsePost(true);
    url = resolver.getUrl(queryBytes);
    assertEquals("https://dns.google/dns-query", url);
  }

  @Test
  void testPrepareQuery() throws TextParseException {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    Message query = new Message();
    query.getHeader().setID(1234);
    query.addRecord(Record.newRecord(Name.fromString("example.com."), Type.A, DClass.IN), Section.QUESTION);

    Message prepared = resolver.prepareQuery(query);
    assertEquals(0, prepared.getHeader().getID());
    assertNotNull(prepared.getOPT()); // Default OPT added

    resolver.setEDNS(-1, 0, 0, Collections.emptyList());
    prepared = resolver.prepareQuery(query);
    assertNull(prepared.getOPT());
  }

  @Test
  void testSetEDNS() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    resolver.setEDNS(0, 1232, Flags.DO, Collections.emptyList());
    Message query = new Message();
    Message prepared = resolver.prepareQuery(query);
    assertNotNull(prepared.getOPT());
    assertEquals(0, prepared.getOPT().getVersion());
    assertTrue((prepared.getOPT().getFlags() & Flags.DO) != 0);

    assertThrows(IllegalArgumentException.class, () -> resolver.setEDNS(1, 0, 0, Collections.emptyList()));
  }

  @Test
  void testSetTSIGKey() throws TextParseException {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    TSIG key = new TSIG(TSIG.HMAC_SHA256, "keyname.", "YmFzZTY0ZGF0YQ==");
    resolver.setTSIGKey(key);
    Message query = new Message();
    query.addRecord(Record.newRecord(Name.fromString("example.com."), Type.A, DClass.IN), Section.QUESTION);
    Message prepared = resolver.prepareQuery(query);
    assertNotNull(prepared.getTSIG());
  }

  @Test
  void testNoOps() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    resolver.setPort(853);
    resolver.setTCP(true);
    resolver.setIgnoreTruncation(true);
    // Should not throw or change anything visible
  }

  @Test
  void testToString() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    assertEquals("DohResolver {GET https://dns.google/dns-query}", resolver.toString());
    resolver.setUsePost(true);
    assertEquals("DohResolver {POST https://dns.google/dns-query}", resolver.toString());
  }

  @Test
  void testVerifyTSIG() throws TextParseException {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    TSIG key = new TSIG(TSIG.HMAC_SHA256, "keyname.", "YmFzZTY0ZGF0YQ==");

    Message query = new Message();
    query.addRecord(Record.newRecord(Name.fromString("example.com."), Type.A, DClass.IN), Section.QUESTION);
    query.setTSIG(key, Rcode.NOERROR, null);

    Message response = new Message();
    response.getHeader().setID(query.getHeader().getID());
    response.addRecord(query.getQuestion(), Section.QUESTION);
    response.setTSIG(key, Rcode.NOERROR, query.getTSIG());

    // Should not throw
    resolver.verifyTSIG(query, response, response.toWire(), key);
  }

  @Test
  void testFailedFuture() {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    Exception ex = new Exception("test");
    java.util.concurrent.CompletableFuture<Object> f = resolver.failedFuture(ex);
    assertTrue(f.isCompletedExceptionally());
  }

  @Test
  void testTimeoutFailedFuture() throws TextParseException {
    TestDohResolver resolver = new TestDohResolver("https://dns.google/dns-query", 10);
    Message query = new Message();
    query.addRecord(Record.newRecord(Name.fromString("example.com."), Type.A, DClass.IN), Section.QUESTION);

    java.util.concurrent.CompletableFuture<Object> f = resolver.timeoutFailedFuture(query, new Exception("inner"));
    assertTrue(f.isCompletedExceptionally());

    f = resolver.timeoutFailedFuture(query, "extra message", new Exception("inner"));
    assertTrue(f.isCompletedExceptionally());
  }
}
