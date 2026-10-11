// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class RRSIGRecordTest {
  @Test
  void rdataFromString() throws IOException, ParseException {
    Tokenizer t =
        new Tokenizer(
            "NSEC3 10 3 180 20161207204758 20161107195347 31055 example.com. GLqlvFaWiemLree+4WQeR+0ANSEYeuLW/KEWZw9mZPUJ1bcb1OQCxp43 7DNdPCSmS/RqJGiVGtSW8xsGoRgUwOdczL8s4j/z3pVi8wDlhw2jXE0k fGBiOshH+3VjZV4eLlDmDixZ3WmA9gzf0G+qAwRP9tjps2+vqRfXOpoj /UffmcMgZODEDGonHAOX/k35sBL+zIP4k6i6Kq/lpPZd8oxsxCwyxAYl E1oMxeE14TnRZoqCZdAEgvrViF91z/tnMbYAY/JNWYK4iREOuuWTLOox C0hKBsymi3fyLjwZ1NV1Bh3lqYN0rr1uo8ZSZmGrfLdg4l+hO4Xl6kG6 JTn27Q==");
    RRSIGRecord rrsigRecord = new RRSIGRecord();
    rrsigRecord.rdataFromString(t, null);
    assertEquals(10, rrsigRecord.getAlgorithm());
    assertEquals(31055, rrsigRecord.getFootprint());
    assertEquals(Name.fromConstantString("example.com."), rrsigRecord.getSigner());
    assertEquals(50, rrsigRecord.getTypeCovered());
    SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddhhmmss", Locale.US);
    formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
    assertEquals(formatter.parse("20161207204758").toInstant(), rrsigRecord.getExpire());
    assertEquals(formatter.parse("20161107195347").toInstant(), rrsigRecord.getTimeSigned());
  }

  @Test
  void emptySignatureInToWireThrows() {
    DNSOutput out = new DNSOutput();
    RRSIGRecord nullSig =
        new RRSIGRecord(
            Name.root, DClass.IN, 0, 0, 0, 0, Instant.EPOCH, Instant.EPOCH, 0, Name.root, null);
    RRSIGRecord emptySig =
        new RRSIGRecord(
            Name.root,
            DClass.IN,
            0,
            0,
            0,
            0,
            Instant.EPOCH,
            Instant.EPOCH,
            0,
            Name.root,
            new byte[0]);
    assertThatThrownBy(() -> nullSig.rrToWire(out, null, false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageStartingWith("Signature is not set");
    assertThatThrownBy(() -> emptySig.rrToWire(out, null, false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageStartingWith("Signature is not set");
  }

  @Test
  void emptySignatureInToPresentationThrows() {
    RRSIGRecord nullSig =
        new RRSIGRecord(
            Name.root, DClass.IN, 0, 0, 0, 0, Instant.EPOCH, Instant.EPOCH, 0, Name.root, null);
    RRSIGRecord emptySig =
        new RRSIGRecord(
            Name.root,
            DClass.IN,
            0,
            0,
            0,
            0,
            Instant.EPOCH,
            Instant.EPOCH,
            0,
            Name.root,
            new byte[0]);
    assertThatThrownBy(nullSig::rdataToString)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageStartingWith("Signature is not set");
    assertThatThrownBy(emptySig::rdataToString)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageStartingWith("Signature is not set");
  }

  @Test
  void expireBeforeEpochThrows() {
    Instant expire = Instant.EPOCH.plusSeconds(-1);
    assertThatThrownBy(
            () ->
                new RRSIGRecord(
                    Name.root,
                    DClass.IN,
                    0,
                    0,
                    0,
                    0,
                    expire,
                    Instant.EPOCH,
                    0,
                    Name.root,
                    new byte[1]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must be after Unix Epoch");
  }

  @Test
  void timeSignedBeforeEpochThrows() {
    Instant timeSigned = Instant.EPOCH.plusSeconds(-1);
    assertThatThrownBy(
            () ->
                new RRSIGRecord(
                    Name.root,
                    DClass.IN,
                    0,
                    0,
                    0,
                    0,
                    Instant.EPOCH,
                    timeSigned,
                    0,
                    Name.root,
                    new byte[1]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must be after Unix Epoch");
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "19690101000000,19700101000000",
        "19700101000000,19690101000000",
        "19690101000000,19690101000000",
      })
  void invalidDateInPresentationThrows(String expire, String timeSigned) {
    try (Tokenizer t =
        new Tokenizer("NSEC3 10 3 180 " + expire + " " + timeSigned + " 31055 example.com. AQID")) {
      RRSIGRecord r = new RRSIGRecord();
      assertThatThrownBy(() -> r.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class)
          .hasMessageContaining("must be after Unix Epoch");
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "", " ", " \"\"",
      })
  void emptySignatureInPresentationThrows(String suffix) {
    try (Tokenizer t =
        new Tokenizer("NSEC3 10 3 180 20161207204758 20161107195347 31055 example.com." + suffix)) {
      RRSIGRecord r = new RRSIGRecord();
      assertThatThrownBy(() -> r.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class)
          .hasMessageEndingWith("signature is required and must be non-empty");
    }
  }

  @Test
  void emptyCertFromWireThrows() {
    RRSIGRecord r = new RRSIGRecord();
    assertThatThrownBy(
            () ->
                r.rrFromWire(
                    new DNSInput(
                        new byte[] {
                          0, // covered
                          0, // alg
                          0, // labels,
                          0, 0, 0, 0, // orig ttl
                          0, 0, 0, 0, // expire
                          0, 0, 0, 0, // time signed
                          0, 0, // footprint
                          1, // signer name length
                          0, // signer name (root - .)
                          // missing signature
                        })))
        .isInstanceOf(WireParseException.class)
        .hasMessage("signature is required and must be non-empty");
  }
}
