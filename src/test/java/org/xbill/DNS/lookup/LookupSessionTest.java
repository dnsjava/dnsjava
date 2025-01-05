// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.xbill.DNS.DClass.IN;
import static org.xbill.DNS.LookupTest.DUMMY_NAME;
import static org.xbill.DNS.LookupTest.LONG_LABEL;
import static org.xbill.DNS.LookupTest.answer;
import static org.xbill.DNS.LookupTest.fail;
import static org.xbill.DNS.LookupTest.multiAnswer;
import static org.xbill.DNS.Type.A;
import static org.xbill.DNS.Type.AAAA;
import static org.xbill.DNS.Type.CNAME;
import static org.xbill.DNS.Type.DNAME;
import static org.xbill.DNS.Type.MX;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Address;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Cache;
import org.xbill.DNS.Credibility;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SetResponse;
import org.xbill.DNS.Type;
import org.xbill.DNS.WireParseException;
import org.xbill.DNS.hosts.HostsFileParser;

@ExtendWith(MockitoExtension.class)
class LookupSessionTest {
  @Mock Resolver mockResolver;

  @TempDir Path tempDir;

  private static final ARecord LOOPBACK_A =
      new ARecord(DUMMY_NAME, IN, 3600, InetAddress.getLoopbackAddress());
  private static final ARecord EXAMPLE_A = (ARecord) LOOPBACK_A.withName(name("example.com."));
  private static final AAAARecord LOOPBACK_AAAA;
  private static final String INVALID_SERVER_RESPONSE_MESSAGE = "refusing to return it";
  private HostsFileParser lookupSessionTestHostsFileParser;

  static {
    AAAARecord aaaaRecord = null;
    try {
      aaaaRecord =
          new AAAARecord(
              DUMMY_NAME,
              IN,
              3600,
              InetAddress.getByAddress(Address.toByteArray("::1", Address.IPv6)));
    } catch (UnknownHostException e) {
      // cannot happen
    }

    LOOPBACK_AAAA = aaaaRecord;
  }

  @BeforeEach
  void beforeEach() throws URISyntaxException {
    lookupSessionTestHostsFileParser =
        new HostsFileParser(
            Paths.get(LookupSessionTest.class.getResource("/hosts_example").toURI()));
  }

  @AfterEach
  void afterEach() {
    verifyNoMoreInteractions(mockResolver);
  }

  @Test
  void lookupAsync_absoluteQuery() throws InterruptedException, ExecutionException {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("a.b."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.getRecords());

    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "true,REMOVE",
        "true,THROW",
        "false,REMOVE",
        "false,THROW",
      })
  void lookupAsync_absoluteQueryNoExtra(boolean useCache, IrrelevantRecordMode mode)
      throws ExecutionException, InterruptedException {
    wireUpMockResolver(
        mockResolver, query -> multiAnswer(query, name -> new Record[] {LOOPBACK_A, EXAMPLE_A}));

    LookupSession lookupSession = lookupSession(useCache).irrelevantRecordMode(mode).build();
    CompletableFuture<LookupResult> future =
        lookupSession.lookupAsync(name("a.b."), A, IN).toCompletableFuture();
    if (mode == IrrelevantRecordMode.THROW) {
      assertThatThrownBy(future::get)
          .cause()
          .isInstanceOf(LookupFailedException.class)
          .hasMessageContaining(INVALID_SERVER_RESPONSE_MESSAGE);
    } else {
      LookupResult result = future.get();
      assertThat(result.getAliases()).isEmpty();
      assertThat(result.getRecords()).containsExactly(LOOPBACK_A.withName(name("a.b.")));
    }

    assertCacheUnused(useCache, mode, lookupSession);
    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_absoluteQuery_defaultClass() throws InterruptedException, ExecutionException {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("a.b."), A);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.getRecords());

    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_absoluteQueryWithHosts() throws InterruptedException, ExecutionException {
    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .hostsFileParser(lookupSessionTestHostsFileParser)
            .build();
    CompletionStage<LookupResult> resultFuture =
        lookupSession.lookupAsync(name("kubernetes.docker.internal."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(
        singletonList(LOOPBACK_A.withName(name("kubernetes.docker.internal."))),
        result.getRecords());
  }

  @Test
  void lookupAsync_absoluteQueryWithFailedHosts() throws IOException {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NXDOMAIN));
    HostsFileParser mockHosts = mock(HostsFileParser.class);
    when(mockHosts.getAddressForHost(any(), anyInt())).thenThrow(IOException.class);
    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).hostsFileParser(mockHosts).build();

    assertThatThrownBy(
            lookupSession
                    .lookupAsync(name("kubernetes.docker.internal."), A, IN)
                    .toCompletableFuture()
                ::get)
        .cause()
        .isInstanceOf(NoSuchDomainException.class);
  }

  @Test
  void lookupAsync_absoluteQueryWithHostsInvalidType() {
    wireUpMockResolver(mockResolver, query -> fail(query, Rcode.NXDOMAIN));
    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .hostsFileParser(lookupSessionTestHostsFileParser)
            .build();

    assertThatThrownBy(
            lookupSession
                    .lookupAsync(name("kubernetes.docker.internal."), MX, IN)
                    .toCompletableFuture()
                ::get)
        .cause()
        .isInstanceOf(NoSuchDomainException.class);
    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_absoluteAaaaQueryWithHosts() throws InterruptedException, ExecutionException {
    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .hostsFileParser(lookupSessionTestHostsFileParser)
            .build();
    CompletionStage<LookupResult> resultFuture =
        lookupSession.lookupAsync(name("kubernetes.docker.internal."), AAAA, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(
        singletonList(LOOPBACK_AAAA.withName(name("kubernetes.docker.internal."))),
        result.getRecords());
  }

  @Test
  void lookupAsync_relativeQueryWithHosts() throws InterruptedException, ExecutionException {
    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .hostsFileParser(lookupSessionTestHostsFileParser)
            .build();
    CompletionStage<LookupResult> resultFuture =
        lookupSession.lookupAsync(name("kubernetes.docker.internal"), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(
        singletonList(LOOPBACK_A.withName(name("kubernetes.docker.internal."))),
        result.getRecords());
  }

  @Test
  void lookupAsync_relativeQueryWithHostsNdots3() throws InterruptedException, ExecutionException {
    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .ndots(3)
            .hostsFileParser(lookupSessionTestHostsFileParser)
            .build();
    CompletionStage<LookupResult> resultFuture =
        lookupSession.lookupAsync(name("kubernetes.docker.internal"), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(
        singletonList(LOOPBACK_A.withName(name("kubernetes.docker.internal."))),
        result.getRecords());
  }

  @Test
  void lookupAsync_relativeQueryWithInvalidHosts() throws InterruptedException, ExecutionException {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));
    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .hostsFileParser(
                new HostsFileParser(tempDir.resolve("lookupAsync_relativeQueryWithInvalidHosts")))
            .build();
    CompletionStage<LookupResult> resultFuture =
        lookupSession.lookupAsync(name("kubernetes.docker.internal"), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(
        singletonList(LOOPBACK_A.withName(name("kubernetes.docker.internal."))),
        result.getRecords());
    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_absoluteQueryWithCacheMiss() throws InterruptedException, ExecutionException {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));
    Cache mockCache = mock(Cache.class);
    when(mockCache.getDClass()).thenReturn(IN);

    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).cache(mockCache).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("a.b."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.getRecords());

    verify(mockResolver).sendAsync(any(), any(Executor.class));
    verify(mockCache).lookupRecords(name("a.b."), A, Credibility.NORMAL);

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockCache).addMessage(messageCaptor.capture());
    Record question = messageCaptor.getValue().getQuestion();
    assertEquals(IN, question.getDClass());
    assertEquals(A, question.getType());
    assertEquals(name("a.b."), question.getName());

    verifyNoMoreInteractions(mockCache);
  }

  @Test
  void lookupAsync_absoluteQueryWithoutCache() throws InterruptedException, ExecutionException {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));

    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).clearCaches().build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("a.b."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.getRecords());

    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_absoluteQueryWithMultipleCaches()
      throws InterruptedException, ExecutionException {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));
    Cache mockCache1 = mock(Cache.class);
    when(mockCache1.getDClass()).thenReturn(IN);
    Cache mockCache2 = mock(Cache.class);
    when(mockCache2.getDClass()).thenReturn(IN);
    List<Cache> caches = new ArrayList<>(2);
    caches.add(mockCache1);
    caches.add(mockCache2);

    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).caches(caches).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("a.b."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.getRecords());

    verify(mockResolver).sendAsync(any(), any(Executor.class));
    verify(mockCache2).lookupRecords(name("a.b."), A, Credibility.NORMAL);

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockCache2).addMessage(messageCaptor.capture());
    Record question = messageCaptor.getValue().getQuestion();
    assertEquals(IN, question.getDClass());
    assertEquals(A, question.getType());
    assertEquals(name("a.b."), question.getName());

    verifyNoMoreInteractions(mockCache1);
    verifyNoMoreInteractions(mockCache2);
  }

  @Test
  void lookupAsync_absoluteQueryWithCacheHit() throws InterruptedException, ExecutionException {
    Name aName = name("a.b.");

    Cache mockCache = mock(Cache.class);
    SetResponse response = mock(SetResponse.class);
    when(response.isSuccessful()).thenReturn(true);
    when(response.answers()).thenReturn(singletonList(new RRset(LOOPBACK_A.withName(aName))));
    when(mockCache.getDClass()).thenReturn(IN);
    when(mockCache.lookupRecords(aName, A, Credibility.NORMAL)).thenReturn(response);

    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).cache(mockCache).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(aName, A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(aName)), result.getRecords());

    verify(mockCache).lookupRecords(aName, A, Credibility.NORMAL);
    verifyNoMoreInteractions(mockCache);
  }

  @Test
  void lookupAsync_searchPathWithCacheMissAndHit() throws InterruptedException, ExecutionException {

    wireUpMockResolver(mockResolver, q -> answer(q, n -> cname("host.tld.", "another.tld.")));

    Cache mockCache = mock(Cache.class);
    when(mockCache.getDClass()).thenReturn(IN);
    // interestingly, a non-configured mock behaves the same way as a cache miss return value.
    when(mockCache.lookupRecords(name("host.tld."), A, Credibility.NORMAL))
        .thenReturn(mock(SetResponse.class));

    SetResponse anotherTldResponse = mock(SetResponse.class);
    when(anotherTldResponse.isSuccessful()).thenReturn(true);
    when(anotherTldResponse.answers())
        .thenReturn(singletonList(new RRset(LOOPBACK_A.withName(name("another.tld.")))));
    when(mockCache.lookupRecords(name("another.tld."), A, Credibility.NORMAL))
        .thenReturn(anotherTldResponse);

    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .cache(mockCache)
            .searchPath(name("tld."))
            .build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("host"), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("another.tld."))), result.getRecords());

    verify(mockCache).lookupRecords(name("host.tld."), A, Credibility.NORMAL);
    verify(mockCache).addMessage(any());
    verify(mockCache).lookupRecords(name("another.tld."), A, Credibility.NORMAL);
    verifyNoMoreInteractions(mockCache);
  }

  @Test
  void lookupAsync_negativeCacheRecords() throws InterruptedException, ExecutionException {

    Cache mockCache = mock(Cache.class);
    when(mockCache.getDClass()).thenReturn(IN);

    SetResponse first = mock(SetResponse.class);
    when(first.isNXDOMAIN()).thenReturn(true);
    when(mockCache.lookupRecords(name("host.tld1."), A, Credibility.NORMAL)).thenReturn(first);

    SetResponse second = mock(SetResponse.class);
    when(second.isNXRRSET()).thenReturn(true);
    when(mockCache.lookupRecords(name("host.tld2."), A, Credibility.NORMAL)).thenReturn(second);

    SetResponse third = mock(SetResponse.class);
    when(third.isSuccessful()).thenReturn(true);
    when(third.answers())
        .thenReturn(singletonList(new RRset(LOOPBACK_A.withName(name("host.tld3.")))));
    when(mockCache.lookupRecords(name("host.tld3."), A, Credibility.NORMAL)).thenReturn(third);

    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .cache(mockCache)
            .searchPath(asList(name("tld1"), name("tld2"), name("tld3")))
            .build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("host"), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("host.tld3."))), result.getRecords());

    InOrder inOrder = inOrder(mockCache);
    inOrder.verify(mockCache).lookupRecords(name("host.tld1."), A, Credibility.NORMAL);
    inOrder.verify(mockCache).lookupRecords(name("host.tld2."), A, Credibility.NORMAL);
    inOrder.verify(mockCache).lookupRecords(name("host.tld3."), A, Credibility.NORMAL);
    verifyNoMoreInteractions(mockCache);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void lookupAsync_twoCnameRedirectMultipleQueries(boolean useCache) throws Exception {
    Function<Name, Record> nameToRecord =
        name -> {
          switch (name.toString()) {
            case "cname.a.":
              return cname("cname.a.", "cname.b.");
            case "cname.b.":
              return cname("cname.b.", "a.b.");
            default:
              return LOOPBACK_A.withName(name("a.b."));
          }
        };
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    LookupSession lookupSession = lookupSession(useCache).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("cname.a."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.getRecords());
    assertEquals(
        Stream.of(name("cname.a."), name("cname.b.")).collect(Collectors.toList()),
        result.getAliases());
    if (useCache) {
      assertEquals(3, lookupSession.getCache(IN).getSize());
    }
    verify(mockResolver, times(3)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "true,true,REMOVE",
        "true,true,THROW",
        "true,false,REMOVE",
        "true,false,THROW",
        "false,false,REMOVE",
        "false,false,THROW",
        "false,true,REMOVE",
        "false,true,THROW",
      })
  void lookupAsync_twoDnameRedirectOneQuery(
      boolean useCache, boolean includeSyntheticCnames, IrrelevantRecordMode mode)
      throws Exception {
    wireUpMockResolver(
        mockResolver,
        query -> {
          Message answer = new Message(query.getHeader().getID());
          answer.addRecord(query.getQuestion(), Section.QUESTION);
          answer.addRecord(dname("example.org.", "example.net."), Section.ANSWER);
          if (includeSyntheticCnames) {
            answer.addRecord(cname("www.example.org.", "www.example.net."), Section.ANSWER);
          }
          answer.addRecord(dname("example.net.", "example.com."), Section.ANSWER);
          if (includeSyntheticCnames) {
            answer.addRecord(cname("www.example.net.", "www.example.com."), Section.ANSWER);
          }
          answer.addRecord(cname("www.example.com.", "example.com."), Section.ANSWER);
          answer.addRecord(LOOPBACK_A.withName(name("example.com.")), Section.ANSWER);
          return answer;
        });

    LookupSession lookupSession = lookupSession(useCache).irrelevantRecordMode(mode).build();
    CompletionStage<LookupResult> resultFuture =
        lookupSession.lookupAsync(name("www.example.org."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("example.com."))), result.getRecords());
    assertEquals(
        Stream.of(name("www.example.org."), name("www.example.net."), name("www.example.com."))
            .collect(Collectors.toList()),
        result.getAliases());
    if (useCache) {
      assertEquals(4 + (includeSyntheticCnames ? 2 : 0), lookupSession.getCache(IN).getSize());
    }
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void lookupAsync_twoCnameRedirectOneQuery(boolean useCache) throws Exception {
    wireUpMockResolver(
        mockResolver,
        query -> {
          Message answer = new Message(query.getHeader().getID());
          answer.addRecord(query.getQuestion(), Section.QUESTION);
          answer.addRecord(cname("cname.a.", "cname.b."), Section.ANSWER);
          answer.addRecord(cname("cname.b.", "a.b."), Section.ANSWER);
          answer.addRecord(LOOPBACK_A.withName(name("a.b.")), Section.ANSWER);
          return answer;
        });

    LookupSession lookupSession = lookupSession(useCache).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("cname.a."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.getRecords());
    assertEquals(
        Stream.of(name("cname.a."), name("cname.b.")).collect(Collectors.toList()),
        result.getAliases());
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource({
    "true,1", "false,1", "true,2", "false,2",
  })
  void lookupAsync_twoCnameRedirectIncompleteResponse(boolean useCache, int firstResponseCnames)
      throws Exception {
    wireUpMockResolver(
        mockResolver,
        query -> {
          Message answer = new Message(query.getHeader().getID());
          answer.addRecord(query.getQuestion(), Section.QUESTION);
          if (query.getQuestion().getName().equals(name("cname.a."))) {
            answer.addRecord(cname("cname.a.", "cname.b."), Section.ANSWER);
            if (firstResponseCnames == 1) {
              answer.addRecord(cname("cname.b.", "a.b."), Section.ANSWER);
            }
          } else {
            if (firstResponseCnames == 2) {
              answer.addRecord(cname("cname.b.", "a.b."), Section.ANSWER);
            }
            answer.addRecord(LOOPBACK_A.withName(name("a.b.")), Section.ANSWER);
          }
          return answer;
        });

    LookupSession lookupSession = lookupSession(useCache).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("cname.a."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.getRecords());
    assertEquals(
        Stream.of(name("cname.a."), name("cname.b.")).collect(Collectors.toList()),
        result.getAliases());
    if (useCache) {
      assertEquals(3, lookupSession.getCache(IN).getSize());
    }
    verify(mockResolver, times(2)).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_simpleCnameRedirect_oneQuery() throws Exception {
    wireUpMockResolver(
        mockResolver,
        query -> {
          Message answer = new Message(query.getHeader().getID());
          answer.addRecord(query.getQuestion(), Section.QUESTION);
          answer.addRecord(cname("cname.r.", DUMMY_NAME.toString()), Section.ANSWER);
          answer.addRecord(LOOPBACK_A, Section.ANSWER);
          return answer;
        });

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();

    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("cname.r."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A), result.getRecords());
    assertEquals(singletonList(name("cname.r.")), result.getAliases());
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource({
    "true,NXDOMAIN,A",
    "false,NXDOMAIN,A",
    "true,NOERROR,MX",
    "false,NOERROR,MX",
  })
  void lookupAsync_simpleCnameRedirect(boolean useCache, String rcode, String type)
      throws ExecutionException, InterruptedException {
    wireUpMockResolver(
        mockResolver,
        q -> {
          if (q.getQuestion().getName().equals(name("cname.r."))) {
            return answer(q, n -> cname("cname.r.", "a.b."));
          } else {
            return fail(q, Rcode.value(rcode));
          }
        });

    LookupSession lookupSession = lookupSession(useCache).build();
    CompletableFuture<LookupResult> future =
        lookupSession.lookupAsync(name("cname.r."), Type.value(type), IN).toCompletableFuture();

    if (rcode.equals("NXDOMAIN")) {
      assertThatThrownBy(future::get).cause().isInstanceOf(NoSuchDomainException.class);
    } else {
      LookupResult result = future.get();
      assertThat(result.getRecords()).isEmpty();
    }
    verify(mockResolver, times(2)).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_simpleCnameRedirect() throws Exception {
    Name cname = name("cname.r.");
    Name target = name("a.b.");
    Function<Name, Record> nameToRecord =
        name -> cname.equals(name) ? cname(cname, target) : LOOPBACK_A;
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();

    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(cname, A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("a.b."))), result.getRecords());
    assertEquals(singletonList(cname), result.getAliases());
    verify(mockResolver, times(2)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @EnumSource(value = IrrelevantRecordMode.class)
  void lookupAsync_simpleCnameRedirectNoExtra(IrrelevantRecordMode mode)
      throws ExecutionException, InterruptedException {
    Name query = name("cname.r.");
    Name target = name("a.b.");
    Function<Name, Record[]> nameToRecord =
        name ->
            query.equals(name)
                ? new Record[] {cname(query, target)}
                : new Record[] {
                  LOOPBACK_A, EXAMPLE_A,
                };
    wireUpMockResolver(mockResolver, q -> multiAnswer(q, nameToRecord));

    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).irrelevantRecordMode(mode).build();

    CompletableFuture<LookupResult> f =
        lookupSession.lookupAsync(query, A, IN).toCompletableFuture();
    if (mode == IrrelevantRecordMode.REMOVE) {
      LookupResult result = f.get();
      assertThat(result.getRecords()).hasSize(1).containsExactly(LOOPBACK_A.withName(target));
    } else {
      assertThatThrownBy(f::get)
          .cause()
          .isInstanceOf(LookupFailedException.class)
          .hasMessageContaining(INVALID_SERVER_RESPONSE_MESSAGE)
          .rootCause()
          .isInstanceOf(WireParseException.class);
    }

    verify(mockResolver, times(2)).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_cnameQuery() throws Exception {
    Name query = name("cname.r.");
    CNAMERecord response = cname(query, "a.b.");
    Function<Name, Record> nameToRecord = name -> query.equals(name) ? response : LOOPBACK_A;
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();

    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(query, CNAME, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(response), result.getRecords());
    assertEquals(emptyList(), result.getAliases());
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_dnameQuery() throws Exception {
    Name query = name("dname.r.");
    DNAMERecord response = dname(query, "a.b.");
    Function<Name, Record> nameToRecord = name -> name.equals(query) ? response : LOOPBACK_A;
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();

    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(query, DNAME, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(response), result.getRecords());
    assertEquals(emptyList(), result.getAliases());
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "true,REMOVE",
        "true,THROW",
        "false,REMOVE",
        "false,THROW",
      })
  void lookupAsync_cnameQueryExtra(boolean useCache, IrrelevantRecordMode mode)
      throws ExecutionException, InterruptedException {
    Name query = name("cname.r.");
    Name target = name("a.b.");
    CNAMERecord response1 = cname(query, target);
    CNAMERecord response2 = cname(name("additional.r."), target);
    Function<Name, Record[]> nameToRecord =
        name ->
            query.equals(name) ? new Record[] {response1, response2} : new Record[] {LOOPBACK_A};
    wireUpMockResolver(mockResolver, q -> multiAnswer(q, nameToRecord));

    LookupSession lookupSession = lookupSession(useCache, mode).build();
    CompletableFuture<LookupResult> future =
        lookupSession.lookupAsync(query, CNAME, IN).toCompletableFuture();
    if (mode == IrrelevantRecordMode.THROW) {
      assertThatThrownBy(future::get)
          .cause()
          .isInstanceOf(LookupFailedException.class)
          .hasMessageContaining(INVALID_SERVER_RESPONSE_MESSAGE);
    } else {
      LookupResult result = future.get();
      assertThat(result.getAliases()).isEmpty();
      assertThat(result.getRecords()).containsExactly(cname(query, target));
    }

    assertCacheUnused(useCache, mode, lookupSession);
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "true,REMOVE",
        "true,THROW",
        "false,REMOVE",
        "false,THROW",
      })
  void lookupAsync_dnameQueryExtra(boolean useCache, IrrelevantRecordMode mode)
      throws ExecutionException, InterruptedException {
    Name query = name("cname.r.");
    Name target = name("a.b.");
    DNAMERecord response1 = dname(query, target);
    DNAMERecord response2 = dname(name("additional.r."), target);
    Function<Name, Record[]> nameToRecord =
        name ->
            query.equals(name) ? new Record[] {response1, response2} : new Record[] {LOOPBACK_A};
    wireUpMockResolver(mockResolver, q -> multiAnswer(q, nameToRecord));

    LookupSession lookupSession = lookupSession(useCache, mode).build();
    CompletableFuture<LookupResult> future =
        lookupSession.lookupAsync(query, DNAME, IN).toCompletableFuture();
    if (mode == IrrelevantRecordMode.THROW) {
      assertThatThrownBy(future::get)
          .cause()
          .isInstanceOf(LookupFailedException.class)
          .hasMessageContaining(INVALID_SERVER_RESPONSE_MESSAGE);
    } else {
      LookupResult result = future.get();
      assertThat(result.getAliases()).isEmpty();
      assertThat(result.getRecords()).containsExactly(response1);
    }

    assertCacheUnused(useCache, mode, lookupSession);
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_simpleDnameRedirect() throws Exception {
    Name query = name("x.y.to.dname.");
    Function<Name, Record> nameToRecord =
        name -> name.equals(query) ? dname("to.dname.", "to.a.") : LOOPBACK_A;
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();

    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(query, A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("x.y.to.a."))), result.getRecords());
    verify(mockResolver, times(2)).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_simpleDnameRedirectSynthesizedCname() throws Exception {
    Name query = name("x.y.example.org.");
    wireUpMockResolver(
        mockResolver,
        q ->
            multiAnswer(
                q,
                name ->
                    new Record[] {
                      dname("example.org.", "example.net."),
                      cname("x.y.example.org.", "x.y.example.net."),
                      LOOPBACK_A.withName(name("x.y.example.net.")),
                    }));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();

    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(query, A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(singletonList(LOOPBACK_A.withName(name("x.y.example.net."))), result.getRecords());
    assertEquals(singletonList(name("x.y.example.org.")), result.getAliases());
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "x.y.example.com.,x.y.example.org.,REMOVE",
        "x.y.example.com.,x.y.example.org.,THROW",
        "x.y.example.org.,x.y.example.com.,REMOVE",
        "x.y.example.org.,x.y.example.com.,THROW",
      })
  void lookupAsync_simpleDnameRedirectWrongSynthesizedCname(
      String from, String to, IrrelevantRecordMode mode)
      throws ExecutionException, InterruptedException {
    Name query = name("x.y.example.org.");
    wireUpMockResolver(
        mockResolver,
        q ->
            multiAnswer(
                q,
                name ->
                    new Record[] {
                      // Correct
                      dname("example.org.", "example.net."),
                      // Extra and wrong
                      cname(from, to),
                      // Correct
                      LOOPBACK_A.withName(name("x.y.example.net.")),
                      // Extra and wrong
                      LOOPBACK_A.withName(name(to)),
                    }));

    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).irrelevantRecordMode(mode).build();

    CompletableFuture<LookupResult> future =
        lookupSession.lookupAsync(query, A, IN).toCompletableFuture();
    if (mode == IrrelevantRecordMode.THROW) {
      assertThatThrownBy(future::get)
          .cause()
          .isInstanceOf(LookupFailedException.class)
          .hasMessageContaining(INVALID_SERVER_RESPONSE_MESSAGE);
    } else {
      LookupResult result = future.get();
      assertThat(result.getAliases()).containsExactly(name("x.y.example.org."));
      assertThat(result.getRecords())
          .containsExactly(LOOPBACK_A.withName(name("x.y.example.net.")));
    }
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "true,REMOVE",
        "true,THROW",
        "false,REMOVE",
        "false,THROW",
      })
  void lookupAsync_simpleDnameRedirectNoExtra(boolean useCache, IrrelevantRecordMode mode)
      throws ExecutionException, InterruptedException {
    Name queryName = name("x.y.to.dname.");
    wireUpMockResolver(
        mockResolver,
        question ->
            multiAnswer(
                question,
                name ->
                    name.equals(queryName)
                        ? new Record[] {dname("to.dname.", "to.a.")}
                        : new Record[] {
                          // LOOPBACK_A will be transformed to 'x.y.to.a.'
                          LOOPBACK_A, EXAMPLE_A,
                        }));

    LookupSession lookupSession = lookupSession(useCache, mode).build();
    CompletableFuture<LookupResult> future =
        lookupSession.lookupAsync(queryName, A, IN).toCompletableFuture();
    if (mode == IrrelevantRecordMode.THROW) {
      assertThatThrownBy(future::get)
          .cause()
          .isInstanceOf(LookupFailedException.class)
          .hasMessageContaining(INVALID_SERVER_RESPONSE_MESSAGE);
    } else {
      LookupResult result = future.get();
      assertAll(
          () -> {
            assertThat(result.getAliases()).containsExactly(name("x.y.to.dname."));
            assertThat(result.getRecords()).containsExactly(LOOPBACK_A.withName(name("x.y.to.a.")));
          });
    }

    if (useCache && mode == IrrelevantRecordMode.THROW) {
      // Verify that the invalid response didn't end up in the cache
      Cache cache = lookupSession.getCache(IN);
      verify(cache, times(1)).addMessage(any(Message.class));
      assertEquals(1, cache.getSize());
      assertTrue(cache.lookupRecords(name("example.com."), A, Credibility.NORMAL).isUnknown());
    }

    verify(mockResolver, times(2)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "true,REMOVE",
        "true,THROW",
        "false,REMOVE",
        "false,THROW",
      })
  void lookupAsync_simpleCnameWrongInitial(boolean useCache, IrrelevantRecordMode mode)
      throws ExecutionException, InterruptedException {
    Name query = name("first.example.com.");
    wireUpMockResolver(mockResolver, q -> answer(q, name -> cname("a.", "b.")));

    LookupSession lookupSession = lookupSession(useCache).irrelevantRecordMode(mode).build();
    CompletableFuture<LookupResult> future =
        lookupSession.lookupAsync(query, A, IN).toCompletableFuture();
    if (mode == IrrelevantRecordMode.THROW) {
      assertThatThrownBy(future::get)
          .cause()
          .isInstanceOf(LookupFailedException.class)
          .hasMessageContaining(INVALID_SERVER_RESPONSE_MESSAGE);
    } else {
      LookupResult result = future.get();
      assertThat(result.getAliases()).isEmpty();
      assertThat(result.getRecords()).isEmpty();
    }

    assertCacheUnused(useCache, mode, lookupSession);

    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "true,REMOVE",
        "true,THROW",
        "false,REMOVE",
        "false,THROW",
      })
  void lookupAsync_simpleDnameWrongInitial(boolean useCache, IrrelevantRecordMode mode)
      throws ExecutionException, InterruptedException {
    Name query = name("first.example.com.");
    wireUpMockResolver(mockResolver, q -> answer(q, name -> dname("a.", "b.")));

    LookupSession lookupSession =
        lookupSession(useCache, mode == IrrelevantRecordMode.THROW)
            .irrelevantRecordMode(mode)
            .build();

    CompletableFuture<LookupResult> future =
        lookupSession.lookupAsync(query, A, IN).toCompletableFuture();
    if (mode == IrrelevantRecordMode.THROW) {
      assertThatThrownBy(future::get)
          .cause()
          .isInstanceOf(LookupFailedException.class)
          .hasMessageContaining(INVALID_SERVER_RESPONSE_MESSAGE);
    } else {
      LookupResult result = future.get();
      assertThat(result.getAliases()).isEmpty();
      assertThat(result.getRecords()).isEmpty();
    }

    assertCacheUnused(useCache, mode, lookupSession);
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  private static void assertCacheUnused(
      boolean useCache, IrrelevantRecordMode mode, LookupSession lookupSession) {
    if (useCache && mode == IrrelevantRecordMode.THROW) {
      // Verify that the invalid response didn't end up in the cache
      Cache cache = lookupSession.getCache(IN);
      verify(cache, times(0)).addMessage(any(Message.class));
      assertEquals(0, cache.getSize());
    }
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "3,REMOVE",
        "3,THROW",
        "4,REMOVE",
        "4,THROW",
      })
  void lookupAsync_redirectLoop(int maxRedirects, IrrelevantRecordMode mode) {
    CNAMERecord cnameA = cname("a.", "b.");
    CNAMERecord cnameB = cname("b.", "c.");
    CNAMERecord cnameC = cname("c.", "d.");
    CNAMERecord cnameD = cname("d.", "a.");
    Function<Name, Record> nameToRecord =
        name -> {
          if (name.equals(cnameA.getName())) {
            return cnameA;
          } else if (name.equals(cnameB.getName())) {
            return cnameB;
          } else if (name.equals(cnameC.getName())) {
            return cnameC;
          } else if (name.equals(cnameD.getName())) {
            return cnameD;
          } else {
            throw new RuntimeException("Unexpected query");
          }
        };
    wireUpMockResolver(mockResolver, q -> answer(q, nameToRecord));
    LookupSession lookupSession =
        LookupSession.builder()
            .maxRedirects(maxRedirects)
            .resolver(mockResolver)
            .irrelevantRecordMode(mode)
            .build();

    Class<? extends Throwable> expected =
        maxRedirects == 3 ? RedirectOverflowException.class : RedirectLoopException.class;
    assertThatThrownBy(
            lookupSession.lookupAsync(cnameA.getName(), A, IN).toCompletableFuture()::get)
        .cause()
        .isInstanceOf(expected);
    verify(mockResolver, times(maxRedirects)).sendAsync(any(), any(Executor.class));
  }

  @ParameterizedTest(name = "maxRedirects={0}")
  @ValueSource(ints = {3, 4})
  void lookupAsync_redirectLoopOneAnswer(int maxRedirects) {
    wireUpMockResolver(
        mockResolver,
        query -> {
          Message answer = new Message(query.getHeader().getID());
          answer.addRecord(query.getQuestion(), Section.QUESTION);
          answer.addRecord(cname("a.", "b."), Section.ANSWER);
          answer.addRecord(cname("b.", "c."), Section.ANSWER);
          answer.addRecord(cname("c.", "d."), Section.ANSWER);
          answer.addRecord(cname("d.", "a."), Section.ANSWER);
          return answer;
        });

    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).maxRedirects(maxRedirects).build();

    Class<? extends Throwable> expected =
        maxRedirects == 3 ? RedirectOverflowException.class : RedirectLoopException.class;
    assertThatThrownBy(lookupSession.lookupAsync(name("a."), A, IN).toCompletableFuture()::get)
        .cause()
        .isInstanceOf(expected);
    verify(mockResolver, times(1)).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_NODATA() throws ExecutionException, InterruptedException {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NOERROR));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("a.b."), A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertThat(result.getRecords()).isEmpty();
    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_NXDOMAIN() {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NXDOMAIN));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();
    assertThatThrownBy(lookupSession.lookupAsync(name("a.b."), A, IN).toCompletableFuture()::get)
        .cause()
        .isInstanceOf(NoSuchDomainException.class);
    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_SERVFAIL() {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.SERVFAIL));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();
    assertThatThrownBy(lookupSession.lookupAsync(name("a.b."), A, IN).toCompletableFuture()::get)
        .cause()
        .isInstanceOf(ServerFailedException.class);
    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_unknownFailure() {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NOTIMP));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();
    assertThatThrownBy(lookupSession.lookupAsync(name("a.b."), A, IN).toCompletableFuture()::get)
        .cause()
        .isInstanceOf(LookupFailedException.class);
    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_NXRRSET() {
    wireUpMockResolver(mockResolver, q -> fail(q, Rcode.NXRRSET));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();
    assertThatThrownBy(lookupSession.lookupAsync(name("a.b."), A, IN).toCompletableFuture()::get)
        .cause()
        .isInstanceOf(NoSuchRRSetException.class);
    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_TooLongNameDNAME() {
    wireUpMockResolver(
        mockResolver, q -> answer(q, n -> dname("to.dname.", format("%s.to.a.", LONG_LABEL))));

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();
    Name toLookup = name(format("%s.%s.%s.to.dname.", LONG_LABEL, LONG_LABEL, LONG_LABEL));
    assertThatThrownBy(lookupSession.lookupAsync(toLookup, A, IN).toCompletableFuture()::get)
        .cause()
        .isInstanceOf(InvalidZoneDataException.class);
    verify(mockResolver).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_MultipleCNAMEs() throws ExecutionException, InterruptedException {
    Record testQuestion = Record.newRecord(name("a.b."), A, IN);
    // According to https://docstore.mik.ua/orelly/networking_2ndEd/dns/ch10_07.htm this is
    // apparently something that BIND 4 / BIND 9 before 9.1 could do.
    wireUpMockResolver(
        mockResolver,
        query -> {
          Message answer = new Message(query.getHeader().getID());
          answer.addRecord(testQuestion, Section.QUESTION);
          answer.addRecord(cname(testQuestion.getName(), "target1."), Section.ANSWER);
          answer.addRecord(cname(testQuestion.getName(), "target2."), Section.ANSWER);
          return answer;
        });

    LookupSession lookupSession = LookupSession.builder().resolver(mockResolver).build();
    LookupResult result = lookupSession.lookupAsync(testQuestion).toCompletableFuture().get();

    assertTrue(result.getRecords().isEmpty());
    assertThat(result.getAliases()).containsExactly(testQuestion.getName());

    // Two invocations as the result doesn't include an actual answer
    verify(mockResolver, times(2)).sendAsync(any(), any(Executor.class));
  }

  @Test
  void lookupAsync_searchAppended() throws Exception {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));

    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .searchPath(singletonList(name("example.com")))
            .build();

    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("host"), A, IN);
    LookupResult lookupResult = resultFuture.toCompletableFuture().get();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver).sendAsync(messageCaptor.capture(), any(Executor.class));

    assertThat(messageCaptor.getValue().getSection(Section.QUESTION))
        .containsExactly(Record.newRecord(name("host.example.com."), Type.A, DClass.IN, 0L));

    assertThat(lookupResult.getRecords())
        .containsExactly(LOOPBACK_A.withName(name("host.example.com.")));
  }

  @Test
  void lookupAsync_searchAppendTooLongName() throws Exception {
    wireUpMockResolver(mockResolver, query -> answer(query, name -> LOOPBACK_A));

    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .searchPath(singletonList(name(format("%s.%s.%s", LONG_LABEL, LONG_LABEL, LONG_LABEL))))
            .build();

    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name(LONG_LABEL), A, IN);
    LookupResult lookupResult = resultFuture.toCompletableFuture().get();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver).sendAsync(messageCaptor.capture(), any(Executor.class));

    assertEquals(
        Record.newRecord(name(LONG_LABEL + "."), A, IN, 0L),
        messageCaptor.getValue().getSection(Section.QUESTION).get(0));

    assertEquals(
        singletonList(LOOPBACK_A.withName(name(LONG_LABEL + "."))), lookupResult.getRecords());
  }

  @Test
  void lookupAsync_twoItemSearchPath() throws Exception {
    wireUpMockResolver(
        mockResolver,
        query -> answer(query, name -> name.equals(name("host.a.")) ? null : LOOPBACK_A));

    LookupSession lookupSession =
        LookupSession.builder()
            .resolver(mockResolver)
            .searchPath(asList(name("a"), name("b")))
            .build();

    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(name("host"), A, IN);
    LookupResult lookupResult = resultFuture.toCompletableFuture().get();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver, times(2)).sendAsync(messageCaptor.capture(), any(Executor.class));

    List<Message> allValues = messageCaptor.getAllValues();
    assertEquals(
        Record.newRecord(name("host.a."), Type.A, DClass.IN, 0L),
        allValues.get(0).getSection(Section.QUESTION).get(0));
    assertEquals(
        Record.newRecord(name("host.b."), Type.A, DClass.IN, 0L),
        allValues.get(1).getSection(Section.QUESTION).get(0));

    assertEquals(singletonList(LOOPBACK_A.withName(name("host.b."))), lookupResult.getRecords());
  }

  @Test
  void lookupAsync_absoluteQueryWithCacheNoCycleResults()
      throws InterruptedException, ExecutionException, UnknownHostException {
    Name aName = name("a.b.");
    InetAddress anotherAddress = InetAddress.getByName("192.168.168.1");
    ARecord anotherA = new ARecord(aName, IN, 3600, anotherAddress);

    Cache mockCache = mock(Cache.class);
    when(mockCache.getDClass()).thenReturn(IN);
    SetResponse response = mock(SetResponse.class);
    when(response.isSuccessful()).thenReturn(true);
    RRset rrSet = new RRset();
    rrSet.addRR(LOOPBACK_A.withName(aName));
    rrSet.addRR(anotherA);
    when(response.answers()).thenReturn(singletonList(rrSet));
    when(mockCache.lookupRecords(aName, A, Credibility.NORMAL)).thenReturn(response);

    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).cache(mockCache).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(aName, A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(asList(LOOPBACK_A.withName(aName), anotherA), result.getRecords());

    // should come out in the other order on the second try
    resultFuture = lookupSession.lookupAsync(aName, A, IN);
    result = resultFuture.toCompletableFuture().get();
    assertEquals(asList(LOOPBACK_A.withName(aName), anotherA), result.getRecords());

    verify(mockCache, times(2)).lookupRecords(aName, A, Credibility.NORMAL);
    verifyNoMoreInteractions(mockCache);
  }

  @Test
  void lookupAsync_absoluteQueryWithCacheCycleResults()
      throws InterruptedException, ExecutionException, UnknownHostException {
    Name aName = name("a.b.");
    InetAddress anotherAddress = InetAddress.getByName("192.168.168.1");
    ARecord anotherA = new ARecord(aName, IN, 3600, anotherAddress);

    Cache mockCache = mock(Cache.class);
    when(mockCache.getDClass()).thenReturn(IN);
    SetResponse response = mock(SetResponse.class);
    when(response.isSuccessful()).thenReturn(true);
    RRset rrSet = new RRset();
    rrSet.addRR(LOOPBACK_A.withName(aName));
    rrSet.addRR(anotherA);
    when(response.answers()).thenReturn(singletonList(rrSet));
    when(mockCache.lookupRecords(aName, A, Credibility.NORMAL)).thenReturn(response);

    LookupSession lookupSession =
        LookupSession.builder().resolver(mockResolver).cache(mockCache).cycleResults(true).build();
    CompletionStage<LookupResult> resultFuture = lookupSession.lookupAsync(aName, A, IN);

    LookupResult result = resultFuture.toCompletableFuture().get();
    assertEquals(asList(LOOPBACK_A.withName(aName), anotherA), result.getRecords());

    // should come out in the other order on the second try
    resultFuture = lookupSession.lookupAsync(aName, A, IN);
    result = resultFuture.toCompletableFuture().get();
    assertEquals(asList(anotherA, LOOPBACK_A.withName(aName)), result.getRecords());

    verify(mockCache, times(2)).lookupRecords(aName, A, Credibility.NORMAL);
    verifyNoMoreInteractions(mockCache);
  }

  @Test
  void expandName_absolute() {
    LookupSession session = LookupSession.builder().resolver(mockResolver).build();
    List<Name> nameStream = session.expandName(name("a."));
    assertEquals(singletonList(name("a.")), nameStream);
  }

  @Test
  void expandName_singleSearchPath() {
    LookupSession session =
        LookupSession.builder().resolver(mockResolver).searchPath(name("example.com.")).build();
    List<Name> nameStream = session.expandName(name("host"));
    assertEquals(asList(name("host.example.com."), name("host.")), nameStream);
  }

  @Test
  void expandName_notSetSearchPath() {
    LookupSession session = LookupSession.builder().resolver(mockResolver).build();
    List<Name> nameStream = session.expandName(name("host"));
    assertEquals(singletonList(name("host.")), nameStream);
  }

  @Test
  void expandName_searchPathIsMadeAbsolute() {
    LookupSession session =
        LookupSession.builder().resolver(mockResolver).searchPath(name("example.com")).build();
    List<Name> nameStream = session.expandName(name("host"));
    assertEquals(asList(name("host.example.com."), name("host.")), nameStream);
  }

  @Test
  void expandName_defaultNdots() {
    LookupSession session =
        LookupSession.builder().resolver(mockResolver).searchPath(name("example.com")).build();
    List<Name> nameStream = session.expandName(name("a.b"));
    assertEquals(asList(name("a.b."), name("a.b.example.com.")), nameStream);
  }

  @Test
  void expandName_ndotsMoreThanOne() {
    LookupSession session =
        LookupSession.builder()
            .searchPath(name("example.com."))
            .resolver(mockResolver)
            .ndots(2)
            .build();
    List<Name> nameStream = session.expandName(name("a.b"));
    assertEquals(asList(name("a.b.example.com."), name("a.b.")), nameStream);
  }

  private static CNAMERecord cname(String name, String target) {
    return cname(name(name), name(target));
  }

  @SuppressWarnings("SameParameterValue")
  private static CNAMERecord cname(Name name, String target) {
    return cname(name, name(target));
  }

  private static CNAMERecord cname(Name name, Name target) {
    return new CNAMERecord(name, IN, 120, target);
  }

  private static DNAMERecord dname(String name, String target) {
    return dname(name(name), name(target));
  }

  @SuppressWarnings("SameParameterValue")
  private static DNAMERecord dname(Name name, String target) {
    return dname(name, name(target));
  }

  private static DNAMERecord dname(Name name, Name target) {
    return new DNAMERecord(name, IN, 120, target);
  }

  private static Name name(String name) {
    return Name.fromConstantString(name);
  }

  private LookupSession.LookupSessionBuilder lookupSession(boolean useCache) {
    return lookupSession(useCache, false);
  }

  private LookupSession.LookupSessionBuilder lookupSession(
      boolean useCache, IrrelevantRecordMode mode) {
    return lookupSession(useCache, mode, false);
  }

  private LookupSession.LookupSessionBuilder lookupSession(boolean useCache, boolean throwOnUse) {
    return lookupSession(useCache, IrrelevantRecordMode.REMOVE, throwOnUse);
  }

  private LookupSession.LookupSessionBuilder lookupSession(
      boolean useCache, IrrelevantRecordMode mode, boolean throwOnUse) {
    LookupSession.LookupSessionBuilder builder =
        LookupSession.builder().resolver(mockResolver).irrelevantRecordMode(mode);
    if (useCache) {
      Cache cache = spy(new Cache());
      builder.cache(cache);
      if (throwOnUse) {
        lenient()
            .doThrow(new RuntimeException("Unexpected addMessage"))
            .when(cache)
            .addMessage(any(Message.class));
        lenient()
            .doThrow(new RuntimeException("Unexpected addRecord"))
            .when(cache)
            .addRecord(any(Record.class), anyInt());
      }
    }

    return builder;
  }

  private void wireUpMockResolver(Resolver mockResolver, Function<Message, Message> handler) {
    when(mockResolver.sendAsync(any(Message.class), any(Executor.class)))
        .thenAnswer(
            invocation -> {
              Message query = invocation.getArgument(0);
              return CompletableFuture.completedFuture(handler.apply(query));
            });
  }
}
