// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.offset;
import static org.assertj.core.api.Assertions.within;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class LOCRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_0arg() {
    LOCRecord loc = new LOCRecord();
    assertThat(loc.getVPrecision()).isEqualTo(0.0);
    assertThat(loc.getHPrecision()).isEqualTo(0.0);
    assertThat(loc.getAltitude()).isEqualTo(-100000.0);
    assertThat(loc.getLongitude()).isCloseTo(-596.52323, within(0.1));
    assertThat(loc.getLatitude()).isCloseTo(-596.52323, within(0.1));
    assertThat(loc.getSize()).isEqualTo(0.0);
  }

  @Test
  void ctor_9arg() {
    LOCRecord loc = new LOCRecord(n, DClass.IN, 0, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5);
    assertThat(loc.getLatitude()).isEqualTo(1.5);
    assertThat(loc.getLongitude()).isEqualTo(2.5);
    assertThat(loc.getAltitude()).isEqualTo(3.5);
    assertThat(loc.getSize()).isEqualTo(4.5);
    assertThat(loc.getHPrecision()).isEqualTo(5.5);
    assertThat(loc.getVPrecision()).isEqualTo(6.5);
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
    assertThat(loc.getLatitude()).isCloseTo(52.373, within(0.1));
    assertThat(loc.getLongitude()).isCloseTo(4.892, within(0.1));
    assertThat(loc.getAltitude()).isEqualTo(-2.0);
    assertThat(loc.getSize()).isEqualTo(0.0);
    assertThat(loc.getHPrecision()).isEqualTo(10000.0);
    assertThat(loc.getVPrecision()).isEqualTo(10.0);
  }

  @Test
  void rdataFromString2() throws IOException {
    String rr = "42 21 54 N 71 06 18 W -99999.99m 30m 10m 10m";
    Tokenizer t = new Tokenizer(rr);
    LOCRecord loc = new LOCRecord();
    loc.rdataFromString(t, null);
    assertThat(loc.getLatitude()).isCloseTo(42.365, within(0.1));
    assertThat(loc.getLongitude()).isCloseTo(-71.105, within(0.1));
    assertThat(loc.getAltitude()).isEqualTo(-99999.99);
    assertThat(loc.getSize()).isEqualTo(30.0);
    assertThat(loc.getHPrecision()).isEqualTo(10.0);
    assertThat(loc.getVPrecision()).isEqualTo(10.0);
    assertThat(loc.rdataToString()).isEqualTo(rr);
  }

  @Test
  void rdataFromString3() throws IOException {
    String rr = "00 00 1.001 N 71 06 18 W 0m 1m 10000m 10m";
    Tokenizer t = new Tokenizer(rr);
    LOCRecord loc = new LOCRecord();
    loc.rdataFromString(t, null);
    assertThat(loc.getLatitude()).isCloseTo(0.000278, offset(0.000001));
    assertThat(loc.getLongitude()).isEqualTo(-71.105);
    assertThat(loc.getAltitude()).isZero();
    assertThat(loc.rdataToString()).isEqualTo(rr);
  }
}
