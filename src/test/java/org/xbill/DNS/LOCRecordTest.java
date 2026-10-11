// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.offset;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class LOCRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_0arg() {
    LOCRecord loc = new LOCRecord();
    assertEquals(0.0, loc.getVPrecision());
    assertEquals(0.0, loc.getHPrecision());
    assertEquals(-100000.0, loc.getAltitude());
    assertEquals(-596.52323, loc.getLongitude(), 0.1);
    assertEquals(-596.52323, loc.getLatitude(), 0.1);
    assertEquals(0.0, loc.getSize());
  }

  @Test
  void ctor_9arg() {
    LOCRecord loc = new LOCRecord(n, DClass.IN, 0, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5);
    assertEquals(1.5, loc.getLatitude());
    assertEquals(2.5, loc.getLongitude());
    assertEquals(3.5, loc.getAltitude());
    assertEquals(4.5, loc.getSize());
    assertEquals(5.5, loc.getHPrecision());
    assertEquals(6.5, loc.getVPrecision());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "9e10", "10e9", "10e10",
      })
  void validateLocRange(String size) {
    String[] pairs = size.split("e");
    long sizeLong = Integer.parseInt(pairs[0]) * (long) Math.pow(10, Integer.parseInt(pairs[1]));
    assertThatThrownBy(() -> new LOCRecord(n, DClass.IN, 0, 1.5, 2.5, 3.5, sizeLong, 5.5, 6.5))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "9000000001",
        "10000000000",
      })
  void rdataFromStringValidatesSize(String size) {
    try (Tokenizer t =
        new Tokenizer("52 22 23.000 N 4 53 32.000 E -2.00m 0.00m " + size + "m 10m")) {
      LOCRecord l = new LOCRecord();
      assertThatThrownBy(() -> l.rdataFromString(t, Name.root))
          .isInstanceOf(TextParseException.class);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "0e0", "0e1", "9e10", "10e9", "10e10",
      })
  void rrFromWireValidatesSize(String size) {
    String[] pairs = size.split("e");
    DNSOutput out = new DNSOutput();
    out.writeU8((Integer.parseInt(pairs[0]) & 0xF0 << 4) + Integer.parseInt(pairs[1]) & 0xF);
    DNSInput in = new DNSInput(out.toByteArray());
    LOCRecord l = new LOCRecord();
    assertThatThrownBy(() -> l.rrFromWire(in)).isInstanceOf(WireParseException.class);
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m");
    LOCRecord loc = new LOCRecord();
    loc.rdataFromString(t, null);
    assertEquals(52.373, loc.getLatitude(), 0.1);
    assertEquals(4.892, loc.getLongitude(), 0.1);
    assertEquals(-2.0, loc.getAltitude());
    assertEquals(0.0, loc.getSize());
    assertEquals(10000.0, loc.getHPrecision());
    assertEquals(10.0, loc.getVPrecision());
  }

  @Test
  void rdataFromString2() throws IOException {
    String rr = "42 21 54 N 71 06 18 W -99999.99m 30m 10m 10m";
    Tokenizer t = new Tokenizer(rr);
    LOCRecord loc = new LOCRecord();
    loc.rdataFromString(t, null);
    assertEquals(42.365, loc.getLatitude(), 0.1);
    assertEquals(-71.105, loc.getLongitude(), 0.1);
    assertEquals(-99999.99, loc.getAltitude());
    assertEquals(30.0, loc.getSize());
    assertEquals(10.0, loc.getHPrecision());
    assertEquals(10.0, loc.getVPrecision());
    assertThat(loc.rdataToString()).isEqualTo(rr);
  }

  @Test
  void rdataFromString3() throws IOException {
    String rr = "00 00 1.001 N 71 06 18 W 0m 1m 10000m 10m";
    Tokenizer t = new Tokenizer(rr);
    LOCRecord loc = new LOCRecord();
    loc.rdataFromString(t, null);
    assertThat(loc.getLatitude()).isCloseTo(0.000278, offset(0.000001));
    assertEquals(-71.105, loc.getLongitude());
    assertEquals(0, loc.getAltitude());
    assertThat(loc.rdataToString()).isEqualTo(rr);
  }
}
