// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NSEC3RecordTest {
  @Test
  void rdataFromString() throws IOException {
    Tokenizer t =
        new Tokenizer(
            "1 1 10 5053851B PF2TNEL79K4HTCBINCDBE9FPBU5I04KD A NS SOA MX AAAA RRSIG DNSKEY NSEC3PARAM TYPE65534");
    NSEC3Record nsec3Record = new NSEC3Record();
    nsec3Record.rdataFromString(t, null);
    assertEquals(NSEC3Record.Digest.SHA1, nsec3Record.getHashAlgorithm());
    assertEquals(NSEC3Record.Flags.OPT_OUT, nsec3Record.getFlags());
    assertNotNull(nsec3Record.getSalt());
    nsec3Record = new NSEC3Record();
    nsec3Record.rdataFromString(
        new Tokenizer(
            "1 1 10 - PF2TNEL79K4HTCBINCDBE9FPBU5I04KD A NS SOA MX AAAA RRSIG DNSKEY NSEC3PARAM TYPE65534"),
        null);
    assertNull(nsec3Record.getSalt());
  }

  @Test
  void nullNextThrows() {
    assertThatThrownBy(
            () ->
                new NSEC3Record(
                    Name.root, DClass.IN, 0, NSEC3Record.SHA1_DIGEST_ID, 0, 0, null, null, null))
        .isInstanceOf(NullPointerException.class);
  }

  @ParameterizedTest
  @ValueSource(
      ints = {
        0, 256, 1024,
      })
  void nextSizeExceededThrows(int size) {
    assertThatThrownBy(
            () ->
                new NSEC3Record(
                    Name.root,
                    DClass.IN,
                    0,
                    NSEC3Record.SHA1_DIGEST_ID,
                    0,
                    0,
                    null,
                    new byte[size],
                    null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @ValueSource(
      ints = {
        256, 1024,
      })
  void saltSizeExceededThrows(int size) {
    assertThatThrownBy(
            () ->
                new NSEC3Record(
                    Name.root,
                    DClass.IN,
                    0,
                    NSEC3Record.SHA1_DIGEST_ID,
                    0,
                    0,
                    new byte[size],
                    new byte[1],
                    null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void emptyNextFromWireDoesNotParse() {
    NSEC3Record n = new NSEC3Record();
    DNSOutput out = new DNSOutput();
    out.writeU8(NSEC3Record.SHA1_DIGEST_ID); // HashAlg
    out.writeU8(0); // Flags
    out.writeU16(0); // Iterations
    out.writeU8(0); // Salt length
    out.writeU8(0); // Hash length
    DNSInput in = new DNSInput(out.toByteArray());
    assertThatThrownBy(() -> n.rrFromWire(in))
        .isInstanceOf(WireParseException.class)
        .hasMessage("Invalid next hash length");
  }

  @Test
  void emptyNextFromStringDoesNotParse() {
    NSEC3Record n = new NSEC3Record();
    try (Tokenizer st = new Tokenizer("1 0 0 -")) {
      assertThatThrownBy(() -> n.rdataFromString(st, Name.root))
          .isInstanceOf(TextParseException.class)
          .hasMessageEndingWith("expected a base32 string");
    }
  }

  @Test
  void emptyToStringThrows() {
    NSEC3Record n = new NSEC3Record();
    assertThatThrownBy(n::rrToString)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageEndingWith("Record is not initialized");
  }

  @Test
  void emptyToWireThrows() {
    NSEC3Record n = new NSEC3Record();
    DNSOutput out = new DNSOutput();
    assertThatThrownBy(() -> n.rrToWire(out, null, false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageEndingWith("Record is not initialized");
  }
}
