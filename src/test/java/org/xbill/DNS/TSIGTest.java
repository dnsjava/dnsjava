// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.Test;

class TSIGTest {
  @Test
  void TSIG_query() throws IOException {
    TSIG key = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");

    Name qname = Name.fromString("www.example.");
    Record rec = Record.newRecord(qname, Type.A, DClass.IN);
    Message msg = Message.newQuery(rec);
    msg.setTSIG(key, Rcode.NOERROR, null);
    byte[] bytes = msg.toWire(512);
    assertEquals(bytes[11], 1);

    Message parsed = new Message(bytes);
    int result = key.verify(parsed, bytes, null);
    assertEquals(result, Rcode.NOERROR);
    assertTrue(parsed.isSigned());
  }

  @Test
  void TSIG_queryIsLastAddMessageRecord() throws IOException {
    TSIG key = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");

    Name qname = Name.fromString("www.example.");
    Record rec = Record.newRecord(qname, Type.A, DClass.IN);
    OPTRecord opt = new OPTRecord(SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE, 0, 0, 0);
    Message msg = Message.newQuery(rec);
    msg.setTSIG(key, Rcode.NOERROR, null);
    msg.addRecord(opt, Section.ADDITIONAL);
    byte[] bytes = msg.toWire(512);
    assertEquals(bytes[11], 2); // additional RR count, lower byte

    Message parsed = new Message(bytes);
    List<Record> additionalSection = parsed.getSection(Section.ADDITIONAL);
    assertEquals(Type.string(Type.OPT), Type.string(additionalSection.get(0).getType()));
    assertEquals(Type.string(Type.TSIG), Type.string(additionalSection.get(1).getType()));
    int result = key.verify(parsed, bytes, null);
    assertEquals(result, Rcode.NOERROR);
    assertTrue(parsed.isSigned());
  }

  @Test
  void TSIG_queryAndTsigApplyMisbehaves() throws IOException {
    Name qname = Name.fromString("www.example.com.");
    Record rec = Record.newRecord(qname, Type.A, DClass.IN);
    OPTRecord opt = new OPTRecord(SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE, 0, 0, 0);
    Message msg = Message.newQuery(rec);
    msg.addRecord(opt, Section.ADDITIONAL);
    assertFalse(msg.isSigned());

    TSIG key = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");
    key.apply(msg, null); // additional RR count, lower byte
    byte[] bytes = msg.toWire(Message.MAXLENGTH);

    assertThrows(WireParseException.class, () -> new Message(bytes), "Expected TSIG error");
  }

  @Test
  void TSIG_queryIsLastResolver() throws IOException {
    Name qname = Name.fromString("www.example.com.");
    Record rec = Record.newRecord(qname, Type.A, DClass.IN);
    Message msg = Message.newQuery(rec);

    TSIG key = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");
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
    res.setTSIGKey(key);
    Message parsed = res.send(msg);

    List<Record> additionalSection = parsed.getSection(Section.ADDITIONAL);
    assertEquals(Type.string(Type.OPT), Type.string(additionalSection.get(0).getType()));
    assertEquals(Type.string(Type.TSIG), Type.string(additionalSection.get(1).getType()));
    int result = key.verify(parsed, parsed.toWire(), null);
    assertEquals(result, Rcode.NOERROR);
    assertTrue(parsed.isSigned());
  }

  @Test
  void TSIG_response() throws IOException {
    TSIG key = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");

    Name qname = Name.fromString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    query.setTSIG(key, Rcode.NOERROR, null);
    byte[] qbytes = query.toWire();
    Message qparsed = new Message(qbytes);

    Message response = new Message(query.getHeader().getID());
    response.setTSIG(key, Rcode.NOERROR, qparsed.getTSIG());
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(question, Section.QUESTION);
    Record answer = Record.fromString(qname, Type.A, DClass.IN, 300, "1.2.3.4", null);
    response.addRecord(answer, Section.ANSWER);
    byte[] bytes = response.toWire(512);

    Message parsed = new Message(bytes);
    int result = key.verify(parsed, bytes, qparsed.getTSIG());
    assertEquals(result, Rcode.NOERROR);
    assertTrue(parsed.isSigned());
  }

  @Test
  void TSIG_truncated() throws IOException {
    TSIG key = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");

    Name qname = Name.fromString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    query.setTSIG(key, Rcode.NOERROR, null);
    byte[] qbytes = query.toWire();
    Message qparsed = new Message(qbytes);

    Message response = new Message(query.getHeader().getID());
    response.setTSIG(key, Rcode.NOERROR, qparsed.getTSIG());
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(question, Section.QUESTION);
    for (int i = 0; i < 40; i++) {
      Record answer = Record.fromString(qname, Type.TXT, DClass.IN, 300, "foo" + i, null);
      response.addRecord(answer, Section.ANSWER);
    }
    byte[] bytes = response.toWire(512);

    Message parsed = new Message(bytes);
    assertTrue(parsed.getHeader().getFlag(Flags.TC));
    int result = key.verify(parsed, bytes, qparsed.getTSIG());
    assertEquals(result, Rcode.NOERROR);
    assertTrue(parsed.isSigned());
  }

  @Test
  void rdataFromString() {
    TextParseException thrown =
        assertThrows(
            TextParseException.class,
            () -> new TSIGRecord().rdataFromString(new Tokenizer(" "), null));
    assertTrue(thrown.getMessage().contains("no text format defined for TSIG"));
  }
}
