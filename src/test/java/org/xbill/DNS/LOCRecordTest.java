// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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

  @Test
  void ctor_9argAcceptsRfcBoundaries() {
    LOCRecord loc =
        new LOCRecord(n, DClass.IN, 0, 90, 180, 42849672.95, 90000000, 90000000, 90000000);
    assertThat(loc.getLatitude()).isEqualTo(90);
    assertThat(loc.getLongitude()).isEqualTo(180);
    assertThat(loc.getAltitude()).isEqualTo(42849672.95);
    assertThat(loc.getSize()).isEqualTo(90000000);
    assertThat(loc.getHPrecision()).isEqualTo(90000000);
    assertThat(loc.getVPrecision()).isEqualTo(90000000);
    assertThat(new LOCRecord(n, DClass.IN, 0, 0, 0, -100000, 0, 0, 0).getAltitude())
        .isEqualTo(-100000);
  }

  @ParameterizedTest
  @CsvSource({
    "-1, 5.5, 6.5",
    "90000000.01, 5.5, 6.5",
    "4.5, -1, 6.5",
    "4.5, 90000000.01, 6.5",
    "4.5, 5.5, -1",
    "4.5, 5.5, 90000000.01",
  })
  void ctor_9argValidatesRanges(double size, double hPrecision, double vPrecision) {
    assertThatThrownBy(
            () -> new LOCRecord(n, DClass.IN, 0, 1.5, 2.5, 3.5, size, hPrecision, vPrecision))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @CsvSource({
    "90.0001, 0, 0",
    "-90.0001, 0, 0",
    "0, 180.0001, 0",
    "0, -180.0001, 0",
    "0, 0, -100000.01",
    "0, 0, 42849672.96",
  })
  void ctor_9argValidatesPositionAndAltitudeRanges(
      double latitude, double longitude, double altitude) {
    assertThatThrownBy(() -> new LOCRecord(n, DClass.IN, 0, latitude, longitude, altitude, 1, 1, 1))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @CsvSource({
    "NaN, 0, 0, 0, 0, 0",
    "0, NaN, 0, 0, 0, 0",
    "0, 0, NaN, 0, 0, 0",
    "0, 0, 0, NaN, 0, 0",
    "0, 0, 0, 0, NaN, 0",
    "0, 0, 0, 0, 0, NaN",
  })
  void ctor_9argRejectsNaN(
      double latitude,
      double longitude,
      double altitude,
      double size,
      double hPrecision,
      double vPrecision) {
    assertThatThrownBy(
            () ->
                new LOCRecord(
                    n, DClass.IN, 0, latitude, longitude, altitude, size, hPrecision, vPrecision))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "0 0 0 N 0 0 0 E -100000.01 0m 0m 0m",
        "0 0 0 N 0 0 0 E 42849672.96 0m 0m 0m",
        "91 0 0 N 0 0 0 E 0m",
        "0 0 0 N 181 0 0 E 0m",
        "90 1 N 0 0 0 E 0m",
        "0 0 0 N 180 1 E 0m",
        "90 0 0.001 N 0 0 0 E 0m",
        "0 0 0 N 180 0 0.001 E 0m",
        "0 -1 0 N 0 0 0 E 0m",
        "0 60 0 N 0 0 0 E 0m",
        "0 x 0 N 0 0 0 E 0m",
        "0 0 -0.1 N 0 0 0 E 0m",
        "0 0 60 N 0 0 0 E 0m",
        "0 0 x N 0 0 0 E 0m",
        "0 0 0 NN 0 0 0 E 0m",
        "0 0 0 X 0 0 0 E 0m",
        "0 0 0 N 0 0 0 X 0m",
        "0 0 0 N 0 0 0 S 0m",
        "0 0 0 N 0 0 0 E",
        "0 0 0 N 0 0 0 E x",
        "0 0 0 N 0 0 0 E 0m 0x 0m 0m",
        "0 0 0 N 0 0 0 E 0m -0.01m",
        "0 0 0 N 0 0 0 E 0m 0m -0.01m",
        "0 0 0 N 0 0 0 E 0m 0m 0m -0.01m",
        "0 0 0 N 0 0 0 E 0m 90000000.01m",
        "0 0 0 N 0 0 0 E 0m 0m 90000000.01m",
        "0 0 0 N 0 0 0 E 0m 0m 0m 90000000.01m",
        "0 0 NaN N 0 0 0 E 0m",
        "0 0 0 N 0 0 0 E NaN",
      })
  void rdataFromStringRejectsInvalidInput(String rdata) {
    assertThatThrownBy(() -> parse(rdata)).isInstanceOf(TextParseException.class);
  }

  @Test
  void rdataFromStringDefaultsOmittedSeconds() throws IOException {
    LOCRecord loc = parse("10 30 N 20 15 E 0m");
    assertThat(loc.getLatitude()).isEqualTo(10.5);
    assertThat(loc.getLongitude()).isEqualTo(20.25);
  }

  @Test
  void rdataFromStringAllowsOmittedMinutesSecondsAndUnitSuffixes() throws IOException {
    LOCRecord loc = parse("1 S 2 E -0.01 1 2 3");
    assertThat(loc.getLatitude()).isCloseTo(-1, within(0.000001));
    assertThat(loc.getLongitude()).isCloseTo(2, within(0.000001));
    assertThat(loc.getAltitude()).isEqualTo(-0.01);
    assertThat(loc.getSize()).isEqualTo(1);
    assertThat(loc.getHPrecision()).isEqualTo(2);
    assertThat(loc.getVPrecision()).isEqualTo(3);
    assertThat(loc.rdataToString()).isEqualTo("01 00 0 S 02 00 0 E -0.01m 1m 2m 3m");
  }

  @Test
  void rdataFromStringAcceptsMaximumSecondsAndMinimumValues() throws IOException {
    LOCRecord loc = parse("0 59 59.999 N 0 59 59.999 E -100000m 0m 0m 0m");
    assertThat(loc.getLatitude()).isCloseTo(0.9999997222, within(0.000000001));
    assertThat(loc.getLongitude()).isCloseTo(0.9999997222, within(0.000000001));
    assertThat(loc.getAltitude()).isEqualTo(-100000);
    assertThat(loc.getSize()).isZero();
    assertThat(loc.getHPrecision()).isZero();
    assertThat(loc.getVPrecision()).isZero();
  }

  @ParameterizedTest
  @CsvSource({
    "90 N 180 W 42849672.95m 90000000m, 90, -180, 42849672.95, 90 00 0 N 180 00 0 W 42849672.95m 90000000m 10000m 10m",
    "1 2 3.125 s 4 5 6.5 e -0.01m 1m 1.25m 0m, -1.034201388888889, 4.085138888888889, -0.01, 01 02 3.125 S 04 05 6.500 E -0.01m 1m 1.25m 0m",
  })
  void rdataFromStringParsesPositionDirections(
      String rdata,
      double expectedLatitude,
      double expectedLongitude,
      double expectedAltitude,
      String expectedRdata)
      throws IOException {
    LOCRecord loc = parse(rdata);
    assertThat(loc.getLatitude()).isCloseTo(expectedLatitude, within(0.000001));
    assertThat(loc.getLongitude()).isCloseTo(expectedLongitude, within(0.000001));
    assertThat(loc.getAltitude()).isEqualTo(expectedAltitude);
    assertThat(loc.rdataToString()).isEqualTo(expectedRdata);
  }

  @Test
  void rdataFromStringDefaultsOptionalValues() throws IOException {
    LOCRecord loc = parse("0 0 0 N 0 0 0 E 0m");
    assertThat(loc.getSize()).isEqualTo(1.0);
    assertThat(loc.getHPrecision()).isEqualTo(10000.0);
    assertThat(loc.getVPrecision()).isEqualTo(10.0);
  }

  @Test
  void rrFromWire() throws IOException {
    LOCRecord loc = new LOCRecord();
    loc.rrFromWire(new DNSInput(locWireData(0, 0x12, 0x21, 0x30)));
    assertThat(loc.getSize()).isEqualTo(1.0);
    assertThat(loc.getHPrecision()).isEqualTo(0.2);
    assertThat(loc.getVPrecision()).isEqualTo(0.03);
    assertThat(loc.getLatitude()).isZero();
    assertThat(loc.getLongitude()).isZero();
    assertThat(loc.getAltitude()).isZero();
  }

  @Test
  void rrFromWireAcceptsBoundarySizeAndPrecisionEncodings() throws IOException {
    LOCRecord loc = fromWire(0, 0x12, 0x30);
    assertThat(loc.getSize()).isZero();
    assertThat(loc.getHPrecision()).isEqualTo(1.0);
    assertThat(loc.getVPrecision()).isEqualTo(0.03);

    loc = fromWire(0x99, 0x99, 0x99);
    assertThat(loc.getSize()).isEqualTo(90000000.0);
    assertThat(loc.getHPrecision()).isEqualTo(90000000.0);
    assertThat(loc.getVPrecision()).isEqualTo(90000000.0);
  }

  @Test
  void rrFromWireAcceptsZeroPrecision() throws IOException {
    LOCRecord loc = fromWire(0x10, 0, 0);
    assertThat(loc.getSize()).isEqualTo(0.01);
    assertThat(loc.getHPrecision()).isZero();
    assertThat(loc.getVPrecision()).isZero();
  }

  @Test
  void rrFromWireRejectsInvalidVersion() {
    LOCRecord loc = new LOCRecord();
    assertThatThrownBy(() -> loc.rrFromWire(new DNSInput(locWireData(1, 0, 0x10, 0x10))))
        .isInstanceOf(WireParseException.class)
        .hasMessage("Invalid LOC version");
  }

  @ParameterizedTest
  @ValueSource(ints = {0xA0, 0x0A})
  void rrFromWireRejectsInvalidSizeEncoding(int encoding) {
    LOCRecord loc = new LOCRecord();
    assertThatThrownBy(() -> loc.rrFromWire(new DNSInput(locWireData(0, encoding, 0x10, 0x10))))
        .isInstanceOf(WireParseException.class)
        .hasMessage("Invalid LOC Encoding");
  }

  @ParameterizedTest
  @CsvSource({
    "1, 16, 16",
    "0, 1, 16",
    "0, 16, 1",
  })
  void rrFromWireRejectsZeroBaseWithNonzeroExponent(int size, int hPrecision, int vPrecision) {
    LOCRecord loc = new LOCRecord();
    assertThatThrownBy(
            () -> loc.rrFromWire(new DNSInput(locWireData(0, size, hPrecision, vPrecision))))
        .isInstanceOf(WireParseException.class)
        .hasMessage("Invalid LOC Encoding");
  }

  @Test
  void rrToWireEncodesSizeAndPrecisions() {
    LOCRecord loc = new LOCRecord(n, DClass.IN, 0, 0, 0, 0, 12.34, 5.67, 8.9);
    DNSOutput out = new DNSOutput();
    loc.rrToWire(out, null, false);
    assertThat(out.toByteArray())
        .containsExactly(0, 0x13, 0x52, 0x82, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x98, 0x96, 0x80);
  }

  @Test
  void rrToWireEncodesZeroSizeAndPrecisions() {
    LOCRecord loc = new LOCRecord(n, DClass.IN, 0, 0, 0, 0, 0, 0, 0);
    DNSOutput out = new DNSOutput();
    loc.rrToWire(out, null, false);
    assertThat(out.toByteArray())
        .containsExactly(0, 0, 0, 0, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x98, 0x96, 0x80);
  }

  private static LOCRecord parse(String rdata) throws IOException {
    try (Tokenizer tokenizer = new Tokenizer(rdata)) {
      LOCRecord loc = new LOCRecord();
      loc.rdataFromString(tokenizer, Name.root);
      return loc;
    }
  }

  private static LOCRecord fromWire(int size, int hPrecision, int vPrecision) throws IOException {
    LOCRecord loc = new LOCRecord();
    loc.rrFromWire(new DNSInput(locWireData(0, size, hPrecision, vPrecision)));
    return loc;
  }

  private static byte[] locWireData(int version, int size, int hPrecision, int vPrecision) {
    DNSOutput out = new DNSOutput();
    out.writeU8(version);
    out.writeU8(size);
    out.writeU8(hPrecision);
    out.writeU8(vPrecision);
    out.writeU32(1L << 31);
    out.writeU32(1L << 31);
    out.writeU32(10000000);
    return out.toByteArray();
  }
}
