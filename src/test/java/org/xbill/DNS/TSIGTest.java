// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.xbill.DNS.TSIG.StreamGenerator;
import org.xbill.DNS.utils.base64;

class TSIGTest {
  private final TSIG defaultKey = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");

  @Test
  void signedQuery() throws IOException {
    Record question = Record.newRecord(Name.fromString("www.example."), Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    query.setTSIG(defaultKey);
    byte[] qbytes = query.toWire(512);
    assertEquals(1, qbytes[11]);

    Message qparsed = new Message(qbytes);
    int result = defaultKey.verify(qparsed, qbytes, null);
    assertEquals(Rcode.NOERROR, result);
    assertTrue(qparsed.isSigned());
    assertTrue(qparsed.isVerified());
  }

  /**
   * Check all of the string algorithm names defined in the javadoc. Confirm that java names also
   * allowed, even though undocumented. THis is to conserve backwards compatibility.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "hmac-md5",
        "hmac-md5.sig-alg.reg.int.",
        "hmac-sha1",
        "hmac-sha224",
        "hmac-sha256",
        "hmac-sha256.",
        "hmac-sha384",
        "hmac-sha512",
        // Java names
        "HmacMD5",
        "HmacSHA256"
      })
  void queryStringAlg(String alg) throws IOException {
    TSIG key = new TSIG(alg, "example.", "12345678");

    Record rec = Record.newRecord(Name.fromString("www.example."), Type.A, DClass.IN);
    Message msg = Message.newQuery(rec);
    msg.setTSIG(key);
    byte[] bytes = msg.toWire(512);
    assertEquals(1, bytes[11]);

    Message parsed = new Message(bytes);
    int result = key.verify(parsed, bytes, null);
    assertEquals(Rcode.NOERROR, result);
    assertTrue(parsed.isSigned());
    assertTrue(parsed.isVerified());
  }

  /** Confirm error thrown with illegal algorithm name. */
  @Test
  void queryStringAlgError() {
    assertThrows(
        IllegalArgumentException.class, () -> new TSIG("randomalg", "example.", "12345678"));
  }

  @Test
  void queryIsLastAddMessageRecord() throws IOException {
    Record rec = Record.newRecord(Name.fromString("www.example."), Type.A, DClass.IN);
    OPTRecord opt = new OPTRecord(SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE, 0, 0, 0);
    Message msg = Message.newQuery(rec);
    msg.setTSIG(defaultKey);
    msg.addRecord(opt, Section.ADDITIONAL);
    byte[] bytes = msg.toWire(512);
    assertEquals(2, bytes[11]); // additional RR count, lower byte

    Message parsed = new Message(bytes);
    List<Record> additionalSection = parsed.getSection(Section.ADDITIONAL);
    assertEquals(Type.string(Type.OPT), Type.string(additionalSection.get(0).getType()));
    assertEquals(Type.string(Type.TSIG), Type.string(additionalSection.get(1).getType()));
    int result = defaultKey.verify(parsed, bytes, null);
    assertEquals(Rcode.NOERROR, result);
    assertTrue(parsed.isSigned());
    assertTrue(parsed.isVerified());
  }

  @Test
  void queryAndTsigApplyMisbehaves() throws IOException {
    Record rec = Record.newRecord(Name.fromString("www.example.com."), Type.A, DClass.IN);
    OPTRecord opt = new OPTRecord(SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE, 0, 0, 0);
    Message msg = Message.newQuery(rec);
    msg.addRecord(opt, Section.ADDITIONAL);
    assertFalse(msg.isSigned());
    assertFalse(msg.isVerified());

    defaultKey.apply(msg, null); // additional RR count, lower byte
    byte[] bytes = msg.toWire(Message.MAXLENGTH);

    assertThrows(WireParseException.class, () -> new Message(bytes), "Expected TSIG error");
  }

  @Test
  void tsigInQueryIsLastViaResolver() throws IOException {
    SimpleResolver res =
        new SimpleResolver("127.0.0.1") {
          @Override
          CompletableFuture<Message> sendAsync(Message query, boolean forceTcp, Executor executor) {
            byte[] out = query.toWire(Message.MAXLENGTH);
            try {
              return CompletableFuture.completedFuture(new Message(out));
            } catch (IOException e) {
              CompletableFuture<Message> f = new CompletableFuture<>();
              f.completeExceptionally(e);
              return f;
            }
          }
        };
    res.setTSIGKey(defaultKey);

    Name qname = Name.fromString("www.example.com.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    Message response = res.send(query);

    List<Record> additionalSection = response.getSection(Section.ADDITIONAL);
    assertEquals(Type.string(Type.OPT), Type.string(additionalSection.get(0).getType()));
    assertEquals(Type.string(Type.TSIG), Type.string(additionalSection.get(1).getType()));
    int result = defaultKey.verify(response, response.toWire(), null);
    assertEquals(Rcode.NOERROR, result);
    assertTrue(response.isSigned());
    assertTrue(response.isVerified());
  }

  @Test
  void unsignedQuerySignedResponse() throws IOException {
    Name qname = Name.fromString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);

    Message response = new Message(query.getHeader().getID());
    response.setTSIG(defaultKey, Rcode.NOERROR, null);
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(question, Section.QUESTION);
    Record answer = Record.fromString(qname, Type.A, DClass.IN, 300, "1.2.3.4", null);
    response.addRecord(answer, Section.ANSWER);
    byte[] rbytes = response.toWire(Message.MAXLENGTH);

    Message rparsed = new Message(rbytes);
    int result = defaultKey.verify(rparsed, rbytes, null);
    assertEquals(Rcode.NOERROR, result);
    assertTrue(rparsed.isSigned());
    assertTrue(rparsed.isVerified());
  }

  @Test
  void signedQuerySignedResponse() throws IOException {
    Name qname = Name.fromString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    query.setTSIG(defaultKey);
    byte[] qbytes = query.toWire(Message.MAXLENGTH);
    Message qparsed = new Message(qbytes);
    assertNotNull(query.getGeneratedTSIG());
    assertEquals(query.getGeneratedTSIG(), qparsed.getTSIG());

    Message response = new Message(query.getHeader().getID());
    response.setTSIG(defaultKey, Rcode.NOERROR, qparsed.getTSIG());
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(question, Section.QUESTION);
    Record answer = Record.fromString(qname, Type.A, DClass.IN, 300, "1.2.3.4", null);
    response.addRecord(answer, Section.ANSWER);
    byte[] rbytes = response.toWire(Message.MAXLENGTH);

    Message rparsed = new Message(rbytes);
    int result = defaultKey.verify(rparsed, rbytes, query.getGeneratedTSIG());
    assertEquals(Rcode.NOERROR, result);
    assertTrue(rparsed.isSigned());
    assertTrue(rparsed.isVerified());
  }

  @Test
  void signedQuerySignedResponseViaResolver() throws IOException {
    Name qname = Name.fromString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);

    try (MockedStatic<NioUdpClient> udpClient = Mockito.mockStatic(NioUdpClient.class)) {
      udpClient
          .when(
              () ->
                  NioUdpClient.sendrecv(
                      any(),
                      any(InetSocketAddress.class),
                      any(),
                      any(byte[].class),
                      anyInt(),
                      any(Duration.class)))
          .thenAnswer(
              a -> {
                Message qparsed = new Message(a.getArgument(3, byte[].class));

                Message response = new Message(qparsed.getHeader().getID());
                response.setTSIG(defaultKey, Rcode.NOERROR, qparsed.getTSIG());
                response.getHeader().setFlag(Flags.QR);
                response.addRecord(question, Section.QUESTION);
                Record answer = Record.fromString(qname, Type.A, DClass.IN, 300, "1.2.3.4", null);
                response.addRecord(answer, Section.ANSWER);
                byte[] rbytes = response.toWire(Message.MAXLENGTH);

                CompletableFuture<byte[]> f = new CompletableFuture<>();
                f.complete(rbytes);
                return f;
              });
      SimpleResolver res = new SimpleResolver("127.0.0.1");
      res.setTSIGKey(defaultKey);

      Message responseFromResolver = res.send(query);
      assertTrue(responseFromResolver.isSigned());
      assertTrue(responseFromResolver.isVerified());
    }
  }

  @Test
  void truncated() throws IOException {
    Name qname = Name.fromString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    query.setTSIG(defaultKey, Rcode.NOERROR, null);
    byte[] qbytes = query.toWire(512);
    Message qparsed = new Message(qbytes);

    Message response = new Message(query.getHeader().getID());
    response.setTSIG(defaultKey, Rcode.NOERROR, qparsed.getTSIG());
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(question, Section.QUESTION);
    for (int i = 0; i < 40; i++) {
      Record answer = Record.fromString(qname, Type.TXT, DClass.IN, 300, "foo" + i, null);
      response.addRecord(answer, Section.ANSWER);
    }
    byte[] rbytes = response.toWire(512);

    Message rparsed = new Message(rbytes);
    assertTrue(rparsed.getHeader().getFlag(Flags.TC));
    int result = defaultKey.verify(rparsed, rbytes, qparsed.getTSIG());
    assertEquals(Rcode.NOERROR, result);
    assertTrue(rparsed.isSigned());
    assertTrue(rparsed.isVerified());
  }

  @Test
  void rdataFromString() {
    TextParseException thrown =
        assertThrows(
            TextParseException.class,
            () -> new TSIGRecord().rdataFromString(new Tokenizer(" "), null));
    assertTrue(thrown.getMessage().contains("no text format defined for TSIG"));
  }

  @Test
  void testTSIGMessageClone() throws IOException {
    TSIGRecord old =
        new TSIGRecord(
            Name.fromConstantString("example."),
            DClass.IN,
            0,
            TSIG.HMAC_SHA256,
            Instant.ofEpochSecond(1647025759),
            Duration.ofSeconds(300),
            base64.fromString("zcHnvVwo0Zlsj0WckOO/ctRD2Znh+BjIWnSvTQdvj94="),
            32,
            Rcode.NOERROR,
            null);

    Name qname = Name.fromConstantString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message response = new Message();
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(question, Section.QUESTION);
    response.addRecord(
        new ARecord(qname, DClass.IN, 0, InetAddress.getByName("127.0.0.1")), Section.ANSWER);
    response.setTSIG(defaultKey, Rcode.NOERROR, old);
    byte[] responseBytes = response.toWire(Message.MAXLENGTH);
    assertNotNull(responseBytes);
    assertNotEquals(0, responseBytes.length);

    Message clone = response.clone();
    assertEquals(response.getQuestion(), clone.getQuestion());
    assertEquals(response.getSection(Section.ANSWER), clone.getSection(Section.ANSWER));
    assertEquals(response.getGeneratedTSIG(), clone.getGeneratedTSIG());
    byte[] cloneBytes = clone.toWire(Message.MAXLENGTH);
    assertNotNull(cloneBytes);
    assertNotEquals(0, cloneBytes.length);
  }

  @ParameterizedTest
  @ValueSource(ints = {-1, 0, 101})
  void testStreamGeneratorNthMessageArgument(int signEvery) {
    assertThrows(
        IllegalArgumentException.class,
        () -> new TSIG.StreamGenerator(defaultKey, null, signEvery));
  }

  @Test
  void testTSIGStreamVerifierMissingMinimumTsig() throws Exception {
    MockMessageClient client = new MockMessageClient(defaultKey);
    MockMessageServer server = new MockMessageServer(defaultKey);

    byte[] query = client.createQuery();
    int numResponses = 200;
    List<Message> response = server.handleQuery(query, numResponses, 200);
    Map<Integer, Integer> expectedRcodes = new HashMap<>();
    for (int i = 0; i < numResponses; i++) {
      expectedRcodes.put(i, i < 100 ? Rcode.NOERROR : Rcode.FORMERR);
    }
    expectedRcodes.put(numResponses - 1, Rcode.BADSIG);
    client.validateResponse(query, response, expectedRcodes);
  }

  @ParameterizedTest(name = "testTSIGStreamVerifier(numResponses: {0}, signEvery: {1})")
  @CsvSource({
    "20,1",
    "53,6",
    "105,7",
    "1000,100",
  })
  void testTSIGStreamVerifier(int numResponses, int signEvery) throws Exception {
    MockMessageClient client = new MockMessageClient(defaultKey);
    MockMessageServer server = new MockMessageServer(defaultKey);

    byte[] query = client.createQuery();
    List<Message> response = server.handleQuery(query, numResponses, signEvery);
    Map<Integer, Integer> expectedRcodes = new HashMap<>();
    for (int i = 0; i < numResponses; i++) {
      expectedRcodes.put(i, Rcode.NOERROR);
    }
    client.validateResponse(query, response, expectedRcodes);
  }

  private static class MockMessageClient {
    private final TSIG key;

    MockMessageClient(TSIG key) {
      this.key = key;
    }

    byte[] createQuery() throws TextParseException {
      Name qname = Name.fromString("www.example.");
      Record question = Record.newRecord(qname, Type.A, DClass.IN);
      Message query = Message.newQuery(question);
      query.setTSIG(key);
      return query.toWire(Message.MAXLENGTH);
    }

    public void validateResponse(
        byte[] query, List<Message> responses, Map<Integer, Integer> expectedRcodes)
        throws IOException {
      Message queryMessage = new Message(query);
      TSIG.StreamVerifier verifier = new TSIG.StreamVerifier(key, queryMessage.getTSIG());

      Map<Integer, Integer> actualRcodes = new HashMap<>();
      for (int i = 0; i < responses.size(); i++) {
        Message response = responses.get(i);
        byte[] renderedMessage = response.toWire(Message.MAXLENGTH);
        actualRcodes.put(i, verifier.verify(new Message(renderedMessage), renderedMessage));
      }

      assertEquals(expectedRcodes, actualRcodes);
    }
  }

  private static class MockMessageServer {
    private final TSIG key;

    MockMessageServer(TSIG key) {
      this.key = key;
    }

    List<Message> handleQuery(byte[] queryMessageBytes, int responseMessageCount, int signEvery)
        throws Exception {
      Message parsedQueryMessage = new Message(queryMessageBytes);
      assertNotNull(parsedQueryMessage.getTSIG());

      List<Message> responseMessageList = new LinkedList<>();
      StreamGenerator generator = getStreamGenerator(signEvery, parsedQueryMessage);

      for (int i = 0; i < responseMessageCount; i++) {
        Message response = new Message(parsedQueryMessage.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.addRecord(parsedQueryMessage.getQuestion(), Section.QUESTION);
        Record answer =
            new ARecord(
                parsedQueryMessage.getQuestion().getName(),
                DClass.IN,
                300,
                InetAddress.getByAddress(ByteBuffer.allocate(4).putInt(i).array()));
        response.addRecord(answer, Section.ANSWER);

        generator.generate(response, i == responseMessageCount - 1);
        responseMessageList.add(response);
      }

      return responseMessageList;
    }

    private StreamGenerator getStreamGenerator(int signEvery, Message parsedQueryMessage)
        throws NoSuchFieldException, IllegalAccessException {
      TSIGRecord queryMessageTSIG = parsedQueryMessage.getTSIG();
      StreamGenerator generator;

      // Hack for testing invalid server responses, the constructor would normally prevent such an
      // invalid argument
      if (signEvery > 100) {
        generator = new StreamGenerator(key, queryMessageTSIG, 1);
        Field signEveryNthMessage = StreamGenerator.class.getDeclaredField("signEveryNthMessage");
        signEveryNthMessage.setAccessible(true);
        signEveryNthMessage.set(generator, signEvery);
      } else {
        generator = new StreamGenerator(key, queryMessageTSIG, signEvery);
      }
      return generator;
    }
  }
}
