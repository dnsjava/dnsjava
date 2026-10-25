// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import javax.crypto.spec.SecretKeySpec;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.TSIG.StreamGenerator;
import org.xbill.DNS.io.IoClientFactory;
import org.xbill.DNS.io.TcpIoClient;
import org.xbill.DNS.io.UdpIoClient;
import org.xbill.DNS.utils.base64;

@Slf4j
class TSIGTest {
  private final TSIG defaultKey = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");

  @ParameterizedTest
  @ValueSource(ints = {-3600, 3600})
  void badTimeResponseCanBeVerified(int clockOffsetSeconds) throws IOException {
    Instant serverTime = Instant.parse("2026-01-01T00:00:00Z");
    Clock serverClock = Clock.fixed(serverTime, ZoneId.of("UTC"));
    Clock clientClock = Clock.offset(serverClock, Duration.ofSeconds(clockOffsetSeconds));
    Name keyName = Name.fromString("example.");
    SecretKeySpec secret = new SecretKeySpec(new byte[32], "HmacSHA256");
    TSIG client = new TSIG(TSIG.HMAC_SHA256, keyName, secret, clientClock);
    TSIG server = new TSIG(TSIG.HMAC_SHA256, keyName, secret, serverClock);

    Message query = Message.newQuery(Record.newRecord(keyName, Type.SOA, DClass.IN));
    query.setTSIG(client);
    byte[] queryWire = query.toWire(Message.MAXLENGTH);
    Message received = new Message(queryWire);
    assertThat(server.verify(received, queryWire, null)).isEqualTo(Rcode.BADTIME);

    Message response = new Message(received.getHeader().getID());
    response.getHeader().setFlag(Flags.QR);
    response.getHeader().setRcode(Rcode.NOTAUTH);
    response.addRecord(received.getQuestion(), Section.QUESTION);
    response.setTSIG(server, Rcode.BADTIME, received.getTSIG());
    byte[] responseWire = response.toWire(Message.MAXLENGTH);
    Message parsed = new Message(responseWire);

    assertThat(parsed.getTSIG().getError()).isEqualTo(Rcode.BADTIME);
    assertThat(parsed.getTSIG().getTimeSigned()).isEqualTo(received.getTSIG().getTimeSigned());
    assertThat(parsed.getTSIG().getFudge()).isEqualTo(received.getTSIG().getFudge());
    assertThat(parsed.getTSIG().getOther()).hasSize(6);
    DNSInput other = new DNSInput(parsed.getTSIG().getOther());
    long serverSeconds = ((long) other.readU16() << 32) | other.readU32();
    assertThat(serverSeconds).isEqualTo(serverTime.getEpochSecond());
    assertThat(client.verify(parsed, responseWire, received.getTSIG())).isEqualTo(Rcode.NOERROR);
    assertThat(parsed.isVerified()).isTrue();

    responseWire[responseWire.length - 1] ^= 1;
    assertThat(client.verify(new Message(responseWire), responseWire, received.getTSIG()))
        .isEqualTo(Rcode.BADSIG);
  }

  @Test
  void badTimeResponseUsesRequestFudge() throws IOException {
    TSIGRecord request =
        new TSIGRecord(
            Name.fromString("example."),
            DClass.ANY,
            0,
            TSIG.HMAC_SHA256,
            Instant.parse("2026-01-01T00:00:00Z"),
            Duration.ofSeconds(42),
            new byte[32],
            123,
            Rcode.NOERROR,
            null);
    Message response = new Message(123);

    TSIGRecord tsig = defaultKey.generate(response, response.toWire(), Rcode.BADTIME, request);

    assertThat(tsig.getFudge()).isEqualTo(request.getFudge());
  }

  @Test
  void signedQuery() throws IOException {
    Record question = Record.newRecord(Name.fromString("www.example."), Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    query.setTSIG(defaultKey);
    byte[] qbytes = query.toWire(512);
    assertThat(qbytes[11]).isOne();

    Message qparsed = new Message(qbytes);
    int result = defaultKey.verify(qparsed, qbytes, null);
    assertThat(result).isEqualTo(Rcode.NOERROR);
    assertThat(qparsed.isSigned()).isTrue();
    assertThat(qparsed.isVerified()).isTrue();
  }

  /**
   * Check all the string algorithm names defined in the javadoc. Confirm that java names also
   * allowed, even though undocumented. This is to conserve backwards compatibility.
   */
  @ParameterizedTest
  @CsvSource({
    "hmac-md5,16",
    "hmac-md5.sig-alg.reg.int.,16",
    "hmac-sha1,20",
    "hmac-sha224,28",
    "hmac-sha256,32",
    "hmac-sha256.,32",
    "hmac-sha256-128,16",
    "hmac-sha384,48",
    "hmac-sha384-192,24",
    "hmac-sha512,64",
    "hmac-sha512-256,32",
    // Java names
    "HmacMD5,16",
    "HmacSHA1,20",
    "HmacSHA256,32",
    "HmacSHA256/128,16",
    "hmacsha256/128,16",
  })
  void queryStringAlg(String alg, int signatureLengthBytes) throws IOException {
    TSIG key = new TSIG(alg, "example.", "12345678");

    Record rec = Record.newRecord(Name.fromString("www.example."), Type.A, DClass.IN);
    Message msg = Message.newQuery(rec);
    msg.setTSIG(key);
    byte[] bytes = msg.toWire(512);
    assertThat(bytes[11]).isOne();

    Message parsed = new Message(bytes);
    int result = key.verify(parsed, bytes, null);
    assertThat(result).isEqualTo(Rcode.NOERROR);
    assertThat(parsed.isSigned()).isTrue();
    assertThat(parsed.isVerified()).isTrue();
    assertThat(parsed.getTSIG().getSignature()).hasSize(signatureLengthBytes);
  }

  /** Confirm error thrown with illegal algorithm name. */
  @Test
  void queryStringAlgError() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TSIG("randomalg", "example.", "12345678"));
  }

  @Test
  void queryIsLastAddMessageRecord() throws IOException {
    Record rec = Record.newRecord(Name.fromString("www.example."), Type.A, DClass.IN);
    OPTRecord opt = new OPTRecord(SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE, 0, 0, 0);
    Message msg = Message.newQuery(rec);
    msg.setTSIG(defaultKey);
    msg.addRecord(opt, Section.ADDITIONAL);
    byte[] bytes = msg.toWire(512);
    assertThat(bytes[11]).isEqualTo((byte) 2); // additional RR count, lower byte

    Message parsed = new Message(bytes);
    List<Record> additionalSection = parsed.getSection(Section.ADDITIONAL);
    assertThat(Type.string(additionalSection.get(0).getType())).isEqualTo(Type.string(Type.OPT));
    assertThat(Type.string(additionalSection.get(1).getType())).isEqualTo(Type.string(Type.TSIG));
    int result = defaultKey.verify(parsed, bytes, null);
    assertThat(result).isEqualTo(Rcode.NOERROR);
    assertThat(parsed.isSigned()).isTrue();
    assertThat(parsed.isVerified()).isTrue();
  }

  @Test
  void queryAndTsigApplyMisbehaves() throws IOException {
    Record rec = Record.newRecord(Name.fromString("www.example.com."), Type.A, DClass.IN);
    OPTRecord opt = new OPTRecord(SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE, 0, 0, 0);
    Message msg = Message.newQuery(rec);
    msg.addRecord(opt, Section.ADDITIONAL);
    assertThat(msg.isSigned()).isFalse();
    assertThat(msg.isVerified()).isFalse();

    defaultKey.apply(msg, null); // additional RR count, lower byte
    byte[] bytes = msg.toWire(Message.MAXLENGTH);

    assertThatExceptionOfType(WireParseException.class)
        .as("Expected TSIG error")
        .isThrownBy(() -> new Message(bytes));
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
    assertThat(Type.string(additionalSection.get(0).getType())).isEqualTo(Type.string(Type.OPT));
    assertThat(Type.string(additionalSection.get(1).getType())).isEqualTo(Type.string(Type.TSIG));
    int result = defaultKey.verify(response, response.toWire(), null);
    assertThat(result).isEqualTo(Rcode.NOERROR);
    assertThat(response.isSigned()).isTrue();
    assertThat(response.isVerified()).isTrue();
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
    assertThat(result).isEqualTo(Rcode.NOERROR);
    assertThat(rparsed.isSigned()).isTrue();
    assertThat(rparsed.isVerified()).isTrue();
  }

  @Test
  void signedQuerySignedResponse() throws IOException {
    Name qname = Name.fromString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    query.setTSIG(defaultKey);
    byte[] qbytes = query.toWire(Message.MAXLENGTH);
    Message qparsed = new Message(qbytes);
    assertThat(query.getGeneratedTSIG()).isNotNull();
    assertThat(qparsed.getTSIG()).isEqualTo(query.getGeneratedTSIG());

    Message response = new Message(query.getHeader().getID());
    response.setTSIG(defaultKey, Rcode.NOERROR, qparsed.getTSIG());
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(question, Section.QUESTION);
    Record answer = Record.fromString(qname, Type.A, DClass.IN, 300, "1.2.3.4", null);
    response.addRecord(answer, Section.ANSWER);
    byte[] rbytes = response.toWire(Message.MAXLENGTH);

    Message rparsed = new Message(rbytes);
    int result = defaultKey.verify(rparsed, rbytes, query.getGeneratedTSIG());
    assertThat(result).isEqualTo(Rcode.NOERROR);
    assertThat(rparsed.isSigned()).isTrue();
    assertThat(rparsed.isVerified()).isTrue();
  }

  @Test
  void signedQuerySignedResponseViaForwarder() throws IOException {
    Name qname = Name.fromString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    query.setTSIG(defaultKey);

    // Force tsig-generation
    query.toWire(Message.MAXLENGTH);
    int originalQueryId = query.getHeader().getID();
    assertThat(originalQueryId).isPositive();
    query.getHeader().setID(new Header().getID());
    log.debug(
        "query: id={}, original id={}",
        query.getHeader().getID(),
        query.getGeneratedTSIG().getOriginalID());

    Message response = new Message(query.getHeader().getID());
    response.setTSIG(defaultKey, Rcode.NOERROR, query.getGeneratedTSIG());
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(question, Section.QUESTION);
    Record answer = Record.fromString(qname, Type.A, DClass.IN, 300, "1.2.3.4", null);
    response.addRecord(answer, Section.ANSWER);
    byte[] rbytes = response.toWire(Message.MAXLENGTH);
    log.debug(
        "response: id={}, original id={}",
        response.getHeader().getID(),
        response.getGeneratedTSIG().getOriginalID());

    Message rparsed = new Message(rbytes);
    int result = defaultKey.verify(rparsed, rbytes, query.getGeneratedTSIG());
    assertThat(result).isEqualTo(Rcode.NOERROR);
    assertThat(rparsed.isSigned()).isTrue();
    assertThat(rparsed.isVerified()).isTrue();
  }

  @Test
  void signedQuerySignedResponseViaResolver() throws IOException {
    Name qname = Name.fromString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);

    SimpleResolver res = new SimpleResolver("127.0.0.1");
    res.setIoClientFactory(
        new IoClientFactory() {
          @Override
          public TcpIoClient createOrGetTcpClient() {
            return null;
          }

          @Override
          public UdpIoClient createOrGetUdpClient() {
            UdpIoClient udpClient = mock(UdpIoClient.class);
            when(udpClient.sendAndReceiveUdp(
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
                      Record answer =
                          Record.fromString(qname, Type.A, DClass.IN, 300, "1.2.3.4", null);
                      response.addRecord(answer, Section.ANSWER);
                      byte[] rbytes = response.toWire(Message.MAXLENGTH);

                      CompletableFuture<byte[]> f = new CompletableFuture<>();
                      f.complete(rbytes);
                      return f;
                    });
            return udpClient;
          }
        });
    res.setTSIGKey(defaultKey);

    Message responseFromResolver = res.send(query);
    assertThat(responseFromResolver.isSigned()).isTrue();
    assertThat(responseFromResolver.isVerified()).isTrue();
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
    assertThat(rparsed.getHeader().getFlag(Flags.TC)).isTrue();
    int result = defaultKey.verify(rparsed, rbytes, qparsed.getTSIG());
    assertThat(result).isEqualTo(Rcode.NOERROR);
    assertThat(rparsed.isSigned()).isTrue();
    assertThat(rparsed.isVerified()).isTrue();
  }

  @Test
  void rdataFromString() {
    TextParseException thrown =
        assertThatExceptionOfType(TextParseException.class)
            .isThrownBy(() -> new TSIGRecord().rdataFromString(new Tokenizer(" "), null))
            .actual();
    assertThat(thrown.getMessage()).contains("no text format defined for TSIG");
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
    assertThat(responseBytes).isNotNull().isNotEmpty();

    Message clone = response.clone();
    assertThat(clone.getQuestion()).isEqualTo(response.getQuestion());
    assertThat(clone.getSection(Section.ANSWER)).isEqualTo(response.getSection(Section.ANSWER));
    assertThat(clone.getGeneratedTSIG()).isEqualTo(response.getGeneratedTSIG());
    byte[] cloneBytes = clone.toWire(Message.MAXLENGTH);
    assertThat(cloneBytes).isNotNull().isNotEmpty();
  }

  @ParameterizedTest
  @ValueSource(ints = {-1, 0, 101})
  void testStreamGeneratorNthMessageArgument(int signEvery) {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TSIG.StreamGenerator(defaultKey, null, signEvery));
  }

  @Test
  void testTSIGStreamVerifierMissingMinimumTsig() throws Exception {
    MockMessageClient client = new MockMessageClient(defaultKey);
    int numResponses = 200;
    byte[] query = client.createQuery();
    List<Message> response;
    try (MockMessageServer server = new MockMessageServer(defaultKey, numResponses, 200, false)) {
      server.send(query);
      response = server.getMessages();
    }
    Map<Integer, Integer> expectedRcodes = new HashMap<>();
    for (int i = 0; i < numResponses; i++) {
      expectedRcodes.put(i, i < 100 ? Rcode.NOERROR : Rcode.FORMERR);
    }
    expectedRcodes.put(numResponses - 1, Rcode.BADSIG);
    client.validateResponse(query, response, expectedRcodes, false);
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
    byte[] query = client.createQuery();
    List<Message> response;
    try (MockMessageServer server =
        new MockMessageServer(defaultKey, numResponses, signEvery, false)) {

      server.send(query);
      response = server.getMessages();
    }
    Map<Integer, Integer> expectedRcodes = new HashMap<>();
    for (int i = 0; i < numResponses; i++) {
      expectedRcodes.put(i, Rcode.NOERROR);
    }
    client.validateResponse(query, response, expectedRcodes, true);
  }

  @ParameterizedTest(name = "testTSIGStreamVerifierLastMessage(numResponses: {0}, signEvery: {1})")
  @CsvSource({
    "53,6",
    "105,7",
    "1000,100",
  })
  void testTSIGStreamVerifierLastMessage(int numResponses, int signEvery) throws Exception {
    MockMessageClient client = new MockMessageClient(defaultKey);
    byte[] query = client.createQuery();
    List<Message> response;
    try (MockMessageServer server =
        new MockMessageServer(defaultKey, numResponses, signEvery, true)) {

      server.send(query);
      response = server.getMessages();
    }
    Map<Integer, Integer> expectedRcodes = new HashMap<>();
    for (int i = 0; i < numResponses; i++) {
      expectedRcodes.put(i, Rcode.NOERROR);
    }

    expectedRcodes.put(numResponses - 1, Rcode.FORMERR);
    client.validateResponse(query, response, expectedRcodes, false);
  }

  @Test
  void testFromTcpStream() throws IOException {
    DNSInput request = new DNSInput(IOUtils.resourceToByteArray("/tsig-axfr/request.bin"));
    byte[] queryBytes = request.readByteArray(request.readU16());
    Message query = new Message(queryBytes);
    assertThat(query.getTSIG()).isNotNull();
    TSIG key =
        new TSIG(
            TSIG.HMAC_SHA256,
            Name.fromConstantString("dnssecishardtest."),
            new SecretKeySpec(
                Objects.requireNonNull(
                    base64.fromString("q4Gsu0nYoyub20//PATXhABobmrVUQyqq5TFzYHfC7o=")),
                "HmacSHA256"),
            Clock.fixed(Instant.parse("2023-11-01T20:52:08Z"), ZoneId.of("UTC")));

    TSIG.StreamVerifier verifier = new TSIG.StreamVerifier(key, query.getTSIG());
    DNSInput response = new DNSInput(IOUtils.resourceToByteArray("/tsig-axfr/response.bin"));

    // Use a list, not a map, to keep the message order intact
    List<Map.Entry<Message, byte[]>> messages = new ArrayList<>();
    while (response.remaining() > 0) {
      byte[] messageBytes = response.readByteArray(response.readU16());
      Message message = new Message(messageBytes);
      messages.add(new AbstractMap.SimpleEntry<>(message, messageBytes));
    }

    for (int i = 0; i < messages.size(); i++) {
      Map.Entry<Message, byte[]> e = messages.get(i);
      assertThat(verifier.verify(e.getKey(), e.getValue(), i == messages.size() - 1))
          .isEqualTo(Rcode.NOERROR);
    }
  }

  @Test
  void testLargeMessageIsNotLargerThanMax() {
    Update update = new Update(Name.fromConstantString("zone.example.com."));
    for (int i = 0; i < 3000; i++) {
      TXTRecord r =
          new TXTRecord(
              Name.fromConstantString("name-" + i + ".zone.example.com."), DClass.IN, 900, "a");
      update.absent(r.name, r.type);
      update.add(r);
    }

    TSIG tsigKey = new TSIG(TSIG.HMAC_SHA384, "zone.example.com.", "c2VjcmU=");
    update.setTSIG(tsigKey);
    byte[] wireData = update.toWire(Message.MAXLENGTH);
    assertThat(wireData).hasSizeLessThan(Message.MAXLENGTH);
  }

  @Test
  void testAxfrLastNotSignedError() throws Exception {
    Name name = Name.fromConstantString("example.com.");
    ZoneTransferIn client =
        new ZoneTransferIn(
            name,
            Type.AXFR,
            0,
            false,
            new InetSocketAddress(InetAddress.getLocalHost(), 53),
            defaultKey) {
          @Override
          TCPClient createTcpClient(Duration timeout) throws IOException {
            return new MockMessageServer(defaultKey, 200, 20, true);
          }
        };

    ZoneTransferException exception =
        assertThatExceptionOfType(ZoneTransferException.class)
            .isThrownBy(() -> client.run(new ZoneBuilderAxfrHandler()))
            .actual();
    assertThat(exception.getMessage()).contains(Rcode.TSIGstring(Rcode.FORMERR));
    assertThat(exception.getMessage()).contains("last");
  }

  @Test
  void testAxfr() throws Exception {
    Name name = Name.fromConstantString("example.com.");
    ZoneTransferIn client =
        new ZoneTransferIn(
            name,
            Type.AXFR,
            0,
            false,
            new InetSocketAddress(InetAddress.getLocalHost(), 53),
            defaultKey) {
          @Override
          TCPClient createTcpClient(Duration timeout) throws IOException {
            return new MockMessageServer(defaultKey, 200, 20, false);
          }
        };

    ZoneBuilderAxfrHandler handler = new ZoneBuilderAxfrHandler();
    client.run(handler);
    // soa on first message, + a record on every message, +soa on last message
    assertThat(handler.getRecords().size()).isEqualTo(202);
  }

  @Test
  void invalidAdditionalCount() {
    Message q = Message.newQuery(Record.newRecord(Name.root, Type.A, DClass.IN));
    Message m = new Message();
    m.addRecord(Record.newRecord(Name.root, Type.A, DClass.IN), Section.QUESTION);
    m.addRecord(Record.newRecord(Name.root, Type.A, DClass.IN), Section.ANSWER);
    m.addRecord(
        Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN),
        Section.ADDITIONAL);
    assertDoesNotThrow(m::getTSIG);
    assertDoesNotThrow(() -> m.normalize(q).getTSIG());
  }

  @Test
  void invalidAdditionalCountViaHeader() throws IOException {
    Message q = Message.newQuery(Record.newRecord(Name.root, Type.A, DClass.IN));
    Message m = new Message();
    m.getHeader().setFlag(Flags.TC);
    m.addRecord(Record.newRecord(Name.root, Type.A, DClass.IN), Section.QUESTION);
    m.addRecord(Record.newRecord(Name.root, Type.A, DClass.IN), Section.ANSWER);
    byte[] mOnWire = m.toWire();
    // bytes 0-1 id, 2-3 flags, 4-11 counts; each u16
    mOnWire[11] = 3; // pretend there are 3 additional records
    Message m2 = new Message(mOnWire);
    assertThat(m2.getHeader().getCount(Section.ADDITIONAL)).isZero();
    assertThat(m2.normalize(q).getHeader().getCount(Section.ADDITIONAL)).isZero();
    assertDoesNotThrow(m2::getTSIG);
    assertDoesNotThrow(() -> m2.normalize(q).getTSIG());
  }

  @Getter
  private static class ZoneBuilderAxfrHandler implements ZoneTransferIn.ZoneTransferHandler {
    private final List<Record> records = new ArrayList<>();

    @Override
    public void startAXFR() {}

    @Override
    public void startIXFR() {}

    @Override
    public void startIXFRDeletes(Record soa) {}

    @Override
    public void startIXFRAdds(Record soa) {}

    @Override
    public void handleRecord(Record r) {
      records.add(r);
    }
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
        byte[] query,
        List<Message> responses,
        Map<Integer, Integer> expectedRcodes,
        boolean lastResponseSignedState)
        throws IOException {
      Message queryMessage = new Message(query);
      TSIG.StreamVerifier verifier = new TSIG.StreamVerifier(key, queryMessage.getTSIG());

      Map<Integer, Integer> actualRcodes = new HashMap<>();
      for (int i = 0; i < responses.size(); i++) {
        boolean isLastMessage = i == responses.size() - 1;
        byte[] renderedMessage = responses.get(i).toWire(Message.MAXLENGTH);
        Message messageFromWire = new Message(renderedMessage);
        actualRcodes.put(i, verifier.verify(messageFromWire, renderedMessage, isLastMessage));
        if (isLastMessage) {
          assertThat(lastResponseSignedState).isEqualTo(messageFromWire.isVerified());
        }
      }

      assertThat(actualRcodes).isEqualTo(expectedRcodes);
    }
  }

  private static class MockMessageServer extends TCPClient {
    private final TSIG key;
    private final int responseMessageCount;
    private final int signEvery;
    private final boolean skipLast;
    @Getter private List<Message> messages;
    private int recvCalls;

    MockMessageServer(TSIG key, int responseMessageCount, int signEvery, boolean skipLast)
        throws IOException {
      super(Duration.ZERO);
      this.key = key;
      this.responseMessageCount = responseMessageCount;
      this.signEvery = signEvery;
      this.skipLast = skipLast;
    }

    @Override
    void bind(SocketAddress addr) {
      // do nothing
    }

    @Override
    void connect(SocketAddress addr) {
      // do nothing
    }

    @Override
    public void close() {
      // do nothing
    }

    @Override
    void send(byte[] queryMessageBytes) throws IOException {
      Message parsedQueryMessage = new Message(queryMessageBytes);
      assertThat(parsedQueryMessage.getTSIG()).isNotNull();

      messages = new LinkedList<>();
      StreamGenerator generator;
      try {
        generator = getStreamGenerator(signEvery, parsedQueryMessage);
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new IOException(e);
      }

      Name queryName = parsedQueryMessage.getQuestion().getName();
      Record soa =
          new SOARecord(
              queryName,
              DClass.IN,
              300,
              new Name("ns1", queryName),
              new Name("admin", queryName),
              1,
              3600,
              1,
              3600,
              1800);
      for (int i = 0; i < responseMessageCount; i++) {
        Message response = new Message(parsedQueryMessage.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.addRecord(parsedQueryMessage.getQuestion(), Section.QUESTION);
        if (i == 0) {
          response.addRecord(soa, Section.ANSWER);
        }
        Record answer =
            new ARecord(
                parsedQueryMessage.getQuestion().getName(),
                DClass.IN,
                300,
                InetAddress.getByAddress(ByteBuffer.allocate(4).putInt(i).array()));
        response.addRecord(answer, Section.ANSWER);

        if (i == responseMessageCount - 1) {
          response.addRecord(soa, Section.ANSWER);
        }

        generator.generate(response, !skipLast && i == responseMessageCount - 1);
        messages.add(response);
      }
    }

    @Override
    byte[] recv() {
      return messages.get(recvCalls++).toWire(Message.MAXLENGTH);
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
