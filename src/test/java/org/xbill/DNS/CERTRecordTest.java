// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.utils.base64;

class CERTRecordTest {
  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("PGP 0 0 CAFEBABE");
    CERTRecord cert = new CERTRecord();
    cert.rdataFromString(t, null);
    assertEquals(0, cert.getAlgorithm());
    assertEquals(0, cert.getKeyTag());
    assertArrayEquals(base64.fromString("CAFEBABE"), cert.getCert());
  }

  @Test
  void emptyCertInCtorThrows() {
    assertThatThrownBy(
            () -> new CERTRecord(Name.root, DClass.IN, 0, CERTRecord.PKIX, 0, 0, new byte[0]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("cert is required and must be non-empty");
    assertThatThrownBy(() -> new CERTRecord(Name.root, DClass.IN, 0, CERTRecord.PKIX, 0, 0, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("cert is required and must be non-empty");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "", " ", " \"\"",
      })
  void emptyCertInPresentationThrows(String suffix) {
    try (Tokenizer t = new Tokenizer("PGP 0 0" + suffix)) {
      CERTRecord r = new CERTRecord();
      assertThatThrownBy(() -> r.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class)
          .hasMessage("cert is required and must be non-empty");
    }
  }

  @Test
  void emptyCertFromWireThrows() {
    CERTRecord r = new CERTRecord();
    assertThatThrownBy(
            () ->
                r.rrFromWire(
                    new DNSInput(
                        new byte[] {
                          0, 0, // cert type
                          0, 0, // key tag
                          0, // alg
                          // missing cert
                        })))
        .isInstanceOf(WireParseException.class)
        .hasMessage("cert is required and must be non-empty");
  }
}
