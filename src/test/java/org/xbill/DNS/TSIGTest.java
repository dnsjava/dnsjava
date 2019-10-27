package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
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
  void rdataFromString() throws IOException {
    TextParseException thrown =
        assertThrows(
            TextParseException.class,
            () -> new TSIGRecord().rdataFromString(new Tokenizer(" "), null));
    assertTrue(thrown.getMessage().contains("no text format defined for TSIG"));
  }
}
