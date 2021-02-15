// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.joining;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.xbill.DNS.ResolverConfig.CONFIGPROVIDER_SKIP_INIT;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.util.List;
import java.util.function.Function;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

public class LookupTest {
  public static final Name DUMMY_NAME = Name.fromConstantString("to.be.replaced.");
  public static final String LONG_LABEL =
      IntStream.range(0, 63).mapToObj(i -> "a").collect(joining());

  private Resolver mockResolver;

  @BeforeEach
  void before() {
    System.setProperty(CONFIGPROVIDER_SKIP_INIT, "true");
    mockResolver = Mockito.mock(Resolver.class);
  }

  @AfterEach
  void after() {
    System.clearProperty(CONFIGPROVIDER_SKIP_INIT);
  }

  @Test
  void testRun_absoluteQuery() throws Exception {
    wireUpMockResolver(mockResolver, this::simpleAnswer);

    Record[] results = makeLookupWithResolver(mockResolver, "example.com.").run();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver).send(messageCaptor.capture());

    assertEquals(
        Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN, 0L),
        messageCaptor.getValue().getSection(Section.QUESTION).get(0));

    assertEquals(1, results.length);
  }

  @Test
  void testRun_relativeQueryIsMadeAbsolute() throws Exception {
    wireUpMockResolver(mockResolver, this::simpleAnswer);

    Record[] results = makeLookupWithResolver(mockResolver, "example.com").run();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver).send(messageCaptor.capture());

    assertEquals(
        Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN, 0L),
        messageCaptor.getValue().getSection(Section.QUESTION).get(0));

    assertEquals(1, results.length);
  }

  @Test
  void testRun_searchAppended() throws Exception {
    wireUpMockResolver(mockResolver, this::simpleAnswer);

    Lookup lookup = makeLookupWithResolver(mockResolver, "host");
    lookup.setSearchPath("example.com");
    Record[] results = lookup.run();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver).send(messageCaptor.capture());

    assertEquals(
        Record.newRecord(Name.fromConstantString("host.example.com."), Type.A, DClass.IN, 0L),
        messageCaptor.getValue().getSection(Section.QUESTION).get(0));

    assertEquals(1, results.length);
  }

  @Test
  void testRun_searchPathAndTooManyDots() throws Exception {
    wireUpMockResolver(mockResolver, this::simpleAnswer);

    Lookup lookup = makeLookupWithResolver(mockResolver, "host.subdomain");
    lookup.setSearchPath("example.com");
    Record[] results = lookup.run();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver).send(messageCaptor.capture());

    assertEquals(
        Record.newRecord(Name.fromConstantString("host.subdomain."), Type.A, DClass.IN, 0L),
        messageCaptor.getValue().getSection(Section.QUESTION).get(0));

    assertEquals(1, results.length);
  }

  @Test
  void testRun_firstSearchPathAppendedHitsCNAME() throws Exception {
    wireUpMockResolver(mockResolver, this::maybeCnameAnswer);

    Lookup lookup = makeLookupWithResolver(mockResolver, "hostX");
    lookup.setSearchPath("first.example.com", "second.example.com");
    Record[] results = lookup.run();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver, times(2)).send(messageCaptor.capture());

    List<Message> queries = messageCaptor.getAllValues();

    assertEquals(
        Record.newRecord(
            Name.fromConstantString("hostX.first.example.com."), Type.A, DClass.IN, 0L),
        queries.get(0).getQuestion());
    assertEquals(
        Record.newRecord(Name.fromConstantString("target.example.com."), Type.A, DClass.IN, 0L),
        queries.get(1).getQuestion());

    assertEquals(1, results.length);
    assertEquals(Name.fromConstantString("target.example.com."), results[0].getName());
    assertEquals(
        singletonList(Name.fromConstantString("hostX.first.example.com.")),
        asList(lookup.getAliases()));
  }

  Message maybeCnameAnswer(Message query) {
    return answer(
        query,
        name -> {
          if (name.toString().equals("hostX.first.example.com.")) {
            return new CNAMERecord(
                DUMMY_NAME, DClass.IN, 0, Name.fromConstantString("target.example.com."));
          }
          return new ARecord(DUMMY_NAME, DClass.IN, 0, InetAddress.getLoopbackAddress());
        });
  }

  @Test
  void testRun_firstSearchPathHitsServFail() throws Exception {
    wireUpMockResolver(mockResolver, this::firstSERVFAILThenA);

    Lookup lookup = makeLookupWithResolver(mockResolver, "host2");
    lookup.setSearchPath("first.example.com", "second.example.com");
    Record[] results = lookup.run();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver, times(2)).send(messageCaptor.capture());

    List<Message> queries = messageCaptor.getAllValues();

    assertEquals(
        Record.newRecord(
            Name.fromConstantString("host2.first.example.com."), Type.A, DClass.IN, 0L),
        queries.get(0).getQuestion());
    assertEquals(
        Record.newRecord(
            Name.fromConstantString("host2.second.example.com."), Type.A, DClass.IN, 0L),
        queries.get(1).getQuestion());

    assertEquals(1, results.length);
    assertEquals(Lookup.SUCCESSFUL, lookup.getResult());
  }

  Message firstSERVFAILThenA(Message query) {
    Message answer = new Message(query.getHeader().getID());
    answer.addRecord(query.getQuestion(), Section.QUESTION);
    Name questionName = query.getQuestion().getName();
    if (questionName.equals(Name.fromConstantString("host2.first.example.com."))) {
      answer.getHeader().setRcode(Rcode.SERVFAIL);
    } else {
      Record r = new ARecord(questionName, DClass.IN, 0, InetAddress.getLoopbackAddress());
      answer.addRecord(r, Section.ANSWER);
    }
    return answer;
  }

  @Test
  void testRun_CNAMELoop() throws Exception {
    wireUpMockResolver(mockResolver, this::cnameLoopAnswer);

    Lookup lookup = makeLookupWithResolver(mockResolver, "host");
    lookup.setSearchPath("first.example.com", "second.example.com");
    Record[] results = lookup.run();

    assertNull(results);
    assertEquals(Lookup.UNRECOVERABLE, lookup.getResult());
    assertEquals("CNAME loop", lookup.getErrorString());
  }

  Message cnameLoopAnswer(Message query) {
    return answer(
        query,
        name -> {
          if (name.toString().equals("first.example.com.")) {
            return new CNAMERecord(
                DUMMY_NAME, DClass.IN, 0, Name.fromConstantString("second.example.com."));
          }
          return new CNAMERecord(
              DUMMY_NAME, DClass.IN, 0, Name.fromConstantString("first.example.com."));
        });
  }

  @Test
  void testRun_reuseLookup() throws Exception {
    wireUpMockResolver(mockResolver, this::simpleAnswer);

    Lookup lookup = makeLookupWithResolver(mockResolver, "host");
    lookup.setSearchPath("first.example.com", "second.example.com");
    Record[] results = lookup.run();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver, times(1)).send(messageCaptor.capture());

    List<Message> queries = messageCaptor.getAllValues();

    assertEquals(
        Record.newRecord(Name.fromConstantString("host.first.example.com."), Type.A, DClass.IN, 0L),
        queries.get(0).getQuestion());

    assertEquals(1, results.length);

    results = lookup.run();
    assertEquals(1, results.length);
  }

  @Test
  void testRun_networkError() throws Exception {
    when(mockResolver.send(any())).thenThrow(IOException.class);

    Lookup lookup = makeLookupWithResolver(mockResolver, "host");
    Record[] results = lookup.run();

    assertNull(results);
    assertEquals(Lookup.TRY_AGAIN, lookup.getResult());
    assertEquals("network error", lookup.getErrorString());
  }

  @Test
  void testRun_timeoutError() throws Exception {
    when(mockResolver.send(any())).thenThrow(InterruptedIOException.class);

    Lookup lookup = makeLookupWithResolver(mockResolver, "host");
    Record[] results = lookup.run();

    assertNull(results);
    assertEquals(Lookup.TRY_AGAIN, lookup.getResult());
    assertEquals("timed out", lookup.getErrorString());
  }

  @Test
  void testRun_servFail() {
    wireUpMockResolver(mockResolver, query -> fail(query, Rcode.SERVFAIL));

    Lookup lookup = makeLookupWithResolver(mockResolver, "host");
    Record[] results = lookup.run();

    assertNull(results);
    assertEquals(Lookup.TRY_AGAIN, lookup.getResult());
    assertEquals("SERVFAIL", lookup.getErrorString());
  }

  @Test
  void testRun_notFound() {
    wireUpMockResolver(mockResolver, query -> fail(query, Rcode.NXDOMAIN));

    Lookup lookup = makeLookupWithResolver(mockResolver, "host");
    Record[] results = lookup.run();

    assertNull(results);
    assertEquals(Lookup.HOST_NOT_FOUND, lookup.getResult());
    assertEquals("host not found", lookup.getErrorString());
  }

  @Test
  void testRun_concatenatedNameTooLong() throws Exception {
    wireUpMockResolver(mockResolver, this::simpleAnswer);

    Lookup lookup = makeLookupWithResolver(mockResolver, LONG_LABEL);
    // search path has a suffix that will make the combined name too long
    lookup.setSearchPath(String.format("%s.%s.%s", LONG_LABEL, LONG_LABEL, LONG_LABEL));
    Record[] results = lookup.run();

    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(mockResolver).send(messageCaptor.capture());

    // The current (somewhat surprising) behaviour is that the NameTooLongException is silently
    // ignored, and resolution falls back to converting longName to an absolute name and querying
    // that
    assertEquals(
        Record.newRecord(Name.fromConstantString(LONG_LABEL + "."), Type.A, DClass.IN, 0L),
        messageCaptor.getValue().getSection(Section.QUESTION).get(0));

    assertEquals(1, results.length);
  }

  @Test
  void testNdots1() throws Exception {
    Resolver mockResolver = Mockito.mock(Resolver.class);
    wireUpMockResolver(mockResolver, this::simpleAnswer);
    Lookup l = makeLookupWithResolver(mockResolver, "example.com");
    l.setSearchPath("namespace.svc.cluster.local", "svc.cluster.local", "cluster.local");
    Record[] results = l.run();
    verify(mockResolver).send(any(Message.class));
    assertEquals(1, results.length);
  }

  @Test
  void testNdotsFallbackToAbsolute() throws Exception {
    Resolver mockResolver = Mockito.mock(Resolver.class);
    wireUpMockResolver(mockResolver, this::goodAnswerWhenThreeLabels);
    Lookup l = makeLookupWithResolver(mockResolver, "example.com");
    l.setSearchPath("namespace.svc.cluster.local", "svc.cluster.local", "cluster.local");
    l.setNdots(5);
    Record[] results = l.run();
    verify(mockResolver, times(4)).send(any(Message.class));
    assertEquals(1, results.length);
  }

  @Test
  void testLookup_constructorFailsWithMetaTypes() {
    assertThrows(IllegalArgumentException.class, () -> new Lookup("example.com.", Type.OPT));
  }

  private Message goodAnswerWhenThreeLabels(Message query) {
    return answer(
        query,
        name -> {
          if (name.labels() == 3) {
            return new ARecord(DUMMY_NAME, DClass.IN, 60, InetAddress.getLoopbackAddress());
          } else {
            return null;
          }
        });
  }

  private Lookup makeLookupWithResolver(Resolver resolver, String name) {
    Name queryName = Name.fromConstantString(name);
    Lookup lookup = new Lookup(queryName, Type.A);
    try {
      lookup.setSearchPath((String[]) null);
    } catch (TextParseException e) {
      throw new RuntimeException(e);
    }
    lookup.setCache(null);
    lookup.setResolver(resolver);
    return lookup;
  }

  private void wireUpMockResolver(Resolver mockResolver, Function<Message, Message> handler) {
    try {
      when(mockResolver.send(any(Message.class)))
          .thenAnswer(
              invocation -> {
                Message query = invocation.getArgument(0);
                return handler.apply(query);
              });
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static Message fail(Message query, int code) {
    Message answer = new Message(query.getHeader().getID());
    answer.addRecord(query.getQuestion(), Section.QUESTION);
    answer.getHeader().setRcode(code);
    return answer;
  }

  private Message simpleAnswer(Message query) {
    Record r = new ARecord(DUMMY_NAME, DClass.IN, 60, InetAddress.getLoopbackAddress());
    return answer(query, name -> r);
  }

  public static Message answer(Message query, Function<Name, Record> recordMaker) {
    Message answer = new Message(query.getHeader().getID());
    answer.addRecord(query.getQuestion(), Section.QUESTION);
    Name questionName = query.getQuestion().getName();
    Record response = recordMaker.apply(questionName);
    if (response == null) {
      answer.getHeader().setRcode(Rcode.NXDOMAIN);
    } else {
      if (DUMMY_NAME.equals(response.getName())) {
        response = response.withName(query.getQuestion().getName());
      }
      answer.addRecord(response, Section.ANSWER);
    }
    return answer;
  }
}
