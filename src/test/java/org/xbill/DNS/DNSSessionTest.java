package org.xbill.DNS;

import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.xbill.DNS.DClass.IN;
import static org.xbill.DNS.LookupTest.DUMMY_NAME;
import static org.xbill.DNS.LookupTest.LONG_LABEL;
import static org.xbill.DNS.LookupTest.answer;
import static org.xbill.DNS.LookupTest.fail;
import static org.xbill.DNS.Type.A;
import static org.xbill.DNS.Type.CNAME;
import static org.xbill.DNS.exceptions.AdditionalDetail.NXDOMAIN;
import static org.xbill.DNS.exceptions.AdditionalDetail.NXRRSET;

import java.net.InetAddress;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.Mock;
import org.xbill.DNS.exceptions.InvalidZoneDataException;
import org.xbill.DNS.exceptions.LookupFailedException;
import org.xbill.DNS.exceptions.RedirectOverflowException;
import org.xbill.DNS.exceptions.ServerFailedException;

class DNSSessionTest {

  @Mock Resolver mockResolver = mock(Resolver.class);

  @AfterEach
  public void after() {
    verifyNoMoreInteractions(mockResolver);
  }

  @Test
  public void lookupAsync_absoluteQuery() throws InterruptedException, ExecutionException {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));

    DNSSession dnsSession = new DNSSession(mockResolver);
    CompletionStage<LookupResult> resultFuture =
        dnsSession.lookupAsync(Name.fromConstantString("a.b."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.get());

    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_simpleCnameRedirect() throws Exception {
    Function<Name, Record> nameToRecord =
        name -> name("cname.r.").equals(name) ? cname("cname.r.", "a.b.") : LOOPBACK_A;
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    DNSSession dnsSession = new DNSSession(mockResolver);

    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("cname.r."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.get());
    verify(mockResolver, times(2)).sendAsync(any());
  }

  @Test
  public void lookupAsync_simpleDnameRedirect() throws Exception {
    Function<Name, Record> nameToRecord =
        n -> name("x.y.to.dname.").equals(n) ? dname("to.dname.", "to.a.") : LOOPBACK_A;
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    DNSSession dnsSession = new DNSSession(mockResolver);

    CompletionStage<LookupResult> resultFuture =
        dnsSession.lookupAsync(name("x.y.to.dname."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("x.y.to.a."))), result.get());
    verify(mockResolver, times(2)).sendAsync(any());
  }

  @Test
  public void lookupAsync_redirectLoop() {
    Function<Name, Record> nameToRecord =
        name -> name("a.b.").equals(name) ? cname("a.", "b.") : cname("b.", "a.");
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    DNSSession dnsSession = new DNSSession(mockResolver);
    dnsSession.setMaxRedirects(2);

    CompletionStage<LookupResult> resultFuture =
        dnsSession.lookupAsync(name("first.example.com."), A, IN);

    assertThrowsCause(
        RedirectOverflowException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver, times(3)).sendAsync(any());
  }

  @Test
  public void lookupAsync_NXDOMAIN() throws Exception {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NXDOMAIN));

    DNSSession dnsSession = new DNSSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertEquals(new LookupResult(emptyList(), NXDOMAIN), resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_SERVFAIL() {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.SERVFAIL));

    DNSSession dnsSession = new DNSSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertThrowsCause(ServerFailedException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_unknownFailure() {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NOTIMP));

    DNSSession dnsSession = new DNSSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertThrowsCause(LookupFailedException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_NXRRSET() throws Exception {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NXRRSET));

    DNSSession dnsSession = new DNSSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertEquals(new LookupResult(emptyList(), NXRRSET), resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_TooLongNameDNAME() {
    wireUpMockResolver(
        mockResolver, q -> answer(q, n -> dname("to.dname.", format("%s.to.a.", LONG_LABEL))));

    DNSSession dnsSession = new DNSSession(mockResolver);
    Name toLookup = name(format("%s.%s.%s.to.dname.", LONG_LABEL, LONG_LABEL, LONG_LABEL));
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(toLookup, A, IN);

    assertThrowsCause(
        InvalidZoneDataException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  @Test
  public void lookupAsync_MultipleCNAMEs() {
    // According to https://docstore.mik.ua/orelly/networking_2ndEd/dns/ch10_07.htm this is
    // apparently something
    // that BIND 4 did.
    wireUpMockResolver(mockResolver, DNSSessionTest::multipleCNAMEs);

    DNSSession dnsSession = new DNSSession(mockResolver);
    CompletionStage<LookupResult> resultFuture = dnsSession.lookupAsync(name("a.b."), A, IN);

    assertThrowsCause(
        InvalidZoneDataException.class, () -> resultFuture.toCompletableFuture().get());
    verify(mockResolver).sendAsync(any());
  }

  private static Message multipleCNAMEs(Message query) {
    Message answer = new Message(query.getHeader().getID());
    Record question = query.getQuestion();
    answer.addRecord(question, Section.QUESTION);
    answer.addRecord(
        new CNAMERecord(question.getName(), CNAME, IN, name("target1.")), Section.ANSWER);
    answer.addRecord(
        new CNAMERecord(question.getName(), CNAME, IN, name("target2.")), Section.ANSWER);
    return answer;
  }

  private static final ARecord LOOPBACK_A =
      new ARecord(DUMMY_NAME, IN, 0, InetAddress.getLoopbackAddress());

  private static CNAMERecord cname(String name, String target) {
    return new CNAMERecord(name(name), IN, 0, name(target));
  }

  @SuppressWarnings("SameParameterValue")
  private static DNAMERecord dname(String name, String target) {
    return new DNAMERecord(name(name), IN, 0, name(target));
  }

  private static Name name(String name) {
    return Name.fromConstantString(name);
  }

  @SuppressWarnings("SameParameterValue")
  private <T extends Throwable> void assertThrowsCause(Class<T> ex, Executable executable) {
    Throwable outerException = assertThrows(Throwable.class, executable);
    assertEquals(ex, outerException.getCause().getClass());
  }

  private void wireUpMockResolver(Resolver mockResolver, Function<Message, Message> handler) {
    when(mockResolver.sendAsync(any(Message.class)))
        .thenAnswer(
            invocation -> {
              Message query = invocation.getArgument(0);
              return CompletableFuture.completedFuture(handler.apply(query));
            });
  }
}
