package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class URIRecordTest {
  @Test
  void ctor_0arg() {
    URIRecord r = new URIRecord();
    assertNull(r.getName());
    assertEquals(0, r.getType());
    assertEquals(0, r.getDClass());
    assertEquals(0, r.getTTL());
    assertEquals(0, r.getPriority());
    assertEquals(0, r.getWeight());
    assertEquals("", r.getTarget());
  }

  @Test
  void ctor_6arg() throws TextParseException {
    Name n = Name.fromString("my.name.");
    String target = "http://foo";

    URIRecord r = new URIRecord(n, DClass.IN, 0xABCDEL, 42, 69, target);
    assertEquals(n, r.getName());
    assertEquals(Type.URI, r.getType());
    assertEquals(DClass.IN, r.getDClass());
    assertEquals(0xABCDEL, r.getTTL());
    assertEquals(42, r.getPriority());
    assertEquals(69, r.getWeight());
    assertEquals(target, r.getTarget());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF01 + " \"http://foo:1234/bar?baz=bum\"");

    URIRecord r = new URIRecord();
    r.rdataFromString(t, null);
    assertEquals(0xABCD, r.getPriority());
    assertEquals(0xEF01, r.getWeight());
    assertEquals("http://foo:1234/bar?baz=bum", r.getTarget());
  }

  @Test
  void rdataToWire() throws TextParseException {
    Name n = Name.fromString("my.name.");
    String target = "http://foo";
    byte[] exp =
        new byte[] {
          (byte) 0xbe,
          (byte) 0xef,
          (byte) 0xde,
          (byte) 0xad,
          (byte) 0x68,
          (byte) 0x74,
          (byte) 0x74,
          (byte) 0x70,
          (byte) 0x3a,
          (byte) 0x2f,
          (byte) 0x2f,
          (byte) 0x66,
          (byte) 0x6f,
          (byte) 0x6f
        };

    URIRecord r = new URIRecord(n, DClass.IN, 0xABCDEL, 0xbeef, 0xdead, target);
    DNSOutput out = new DNSOutput();
    r.rrToWire(out, null, true);
    assertArrayEquals(exp, out.toByteArray());
  }

  @Test
  void rrFromWire() throws IOException {
    byte[] raw =
        new byte[] {
          (byte) 0xbe,
          (byte) 0xef,
          (byte) 0xde,
          (byte) 0xad,
          (byte) 0x68,
          (byte) 0x74,
          (byte) 0x74,
          (byte) 0x70,
          (byte) 0x3a,
          (byte) 0x2f,
          (byte) 0x2f,
          (byte) 0x66,
          (byte) 0x6f,
          (byte) 0x6f
        };
    DNSInput in = new DNSInput(raw);

    URIRecord r = new URIRecord();
    r.rrFromWire(in);
    assertEquals(0xBEEF, r.getPriority());
    assertEquals(0xDEAD, r.getWeight());
    assertEquals("http://foo", r.getTarget());
  }

  @Test
  void toobig_priority() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new URIRecord(
                Name.fromString("the.name"), DClass.IN, 0x1234, 0x10000, 42, "http://foo"));
  }

  @Test
  void toosmall_priority() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new URIRecord(Name.fromString("the.name"), DClass.IN, 0x1234, -1, 42, "http://foo"));
  }

  @Test
  void toobig_weight() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new URIRecord(
                Name.fromString("the.name"), DClass.IN, 0x1234, 42, 0x10000, "http://foo"));
  }

  @Test
  void toosmall_weight() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new URIRecord(Name.fromString("the.name"), DClass.IN, 0x1234, 42, -1, "http://foo"));
  }
}
