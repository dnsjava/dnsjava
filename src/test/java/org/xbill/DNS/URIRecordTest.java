// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class URIRecordTest {
  private static final Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_0arg() throws URISyntaxException {
    URIRecord r = new URIRecord();
    assertNull(r.getName());
    assertEquals(0, r.getType());
    assertEquals(0, r.getDClass());
    assertEquals(0, r.getTTL());
    assertEquals(0, r.getPriority());
    assertEquals(0, r.getWeight());
    assertEquals("", r.getTarget());
    assertEquals(new URI(""), r.getTargetAsURI());
  }

  @Test
  void ctor_6arg() throws TextParseException, URISyntaxException {
    String target = "http://foo/bar";

    URIRecord r = new URIRecord(n, DClass.IN, 0xABCDEL, 42, 69, target);
    assertEquals(n, r.getName());
    assertEquals(Type.URI, r.getType());
    assertEquals(DClass.IN, r.getDClass());
    assertEquals(0xABCDEL, r.getTTL());
    assertEquals(42, r.getPriority());
    assertEquals(69, r.getWeight());
    assertEquals("http://foo/bar", r.getTarget());
    assertEquals(new URI("http://foo/bar"), r.getTargetAsURI());
  }

  @Test
  void rdataFromString() throws IOException, URISyntaxException {
    Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF01 + " \"http://foo:1234/bar?baz=bum\"");

    URIRecord r = new URIRecord();
    r.rdataFromString(t, null);
    assertEquals(0xABCD, r.getPriority());
    assertEquals(0xEF01, r.getWeight());
    assertEquals(new URI("http://foo:1234/bar?baz=bum"), r.getTargetAsURI());
  }

  @Test
  void rdataToWire() {
    String target = "http://foo";
    byte[] exp = {
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
  void rrFromWire() throws IOException, URISyntaxException {
    byte[] raw = {
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
    assertEquals(new URI("http://foo"), r.getTargetAsURI());
  }

  @Test
  void toobig_priority() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new URIRecord(n, DClass.IN, 0x1234, 0x10000, 42, "http://foo"));
  }

  @Test
  void toosmall_priority() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new URIRecord(n, DClass.IN, 0x1234, -1, 42, "http://foo"));
  }

  @Test
  void toobig_weight() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new URIRecord(n, DClass.IN, 0x1234, 42, 0x10000, "http://foo"));
  }

  @Test
  void toosmall_weight() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new URIRecord(n, DClass.IN, 0x1234, 42, -1, "http://foo"));
  }

  @Test
  void validateEmptyUriThrows() {
    assertThatThrownBy(() -> new URIRecord(n, DClass.IN, 3600, 1, 1, ""))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new URIRecord(n, DClass.IN, 3600, 1, 1, null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @ValueSource(ints = {1, 256, 300})
  void validateUriLengths(int uriLength) {
    String value = new String(new char[uriLength]);
    URIRecord uri = new URIRecord(n, DClass.IN, 3600, 1, 1, value);
    assertThatThrownBy(uri::getTargetAsURI).isInstanceOf(URISyntaxException.class);
  }

  @Test
  void validateLongUriCanRoundtrip() throws IOException, URISyntaxException {
    String value =
        IntStream.range(0, 360)
            .boxed()
            .map(
                i -> {
                  if (i < 120) {
                    return "a";
                  } else if (i == 120) {
                    return ".";
                  } else if (i < 240) {
                    return "b";
                  } else if (i == 240) {
                    return ".";
                  } else if (i < 360) {
                    return "c";
                  } else if (i == 360) {
                    return ".";
                  }
                  return "d";
                })
            .reduce("http://", (a, b) -> a + b);
    URIRecord uri = new URIRecord(n, DClass.IN, 3600, 1, 1, value);

    URIRecord uri2 = new URIRecord();
    DNSOutput out = new DNSOutput();
    uri.rrToWire(out, null, false);
    uri2.rrFromWire(new DNSInput(out.toByteArray()));
    assertThat(uri2.getTargetAsURI()).hasToString(value);

    URIRecord uri3 = new URIRecord();
    uri3.rdataFromString(new Tokenizer(uri.rrToString()), Name.root);
    assertThat(uri3.getTargetAsURI()).hasToString(value);
  }
}
