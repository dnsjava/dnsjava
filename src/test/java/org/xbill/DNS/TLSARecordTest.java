// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.utils.base16;

class TLSARecordTest {
  @ParameterizedTest
  @ValueSource(strings = {"CAFE", "CAFE CAFFEE"})
  void rdataFromString(String rdata) throws IOException {
    try (Tokenizer t = new Tokenizer("0 0 1 " + rdata)) {
      TLSARecord tlsaRecord = new TLSARecord();
      tlsaRecord.rdataFromString(t, null);
      assertEquals(TLSARecord.CertificateUsage.CA_CONSTRAINT, tlsaRecord.getCertificateUsage());
      assertEquals(TLSARecord.MatchingType.SHA256, tlsaRecord.getMatchingType());
      assertEquals(TLSARecord.Selector.FULL_CERTIFICATE, tlsaRecord.getSelector());
      assertArrayEquals(base16.fromString(rdata), tlsaRecord.getCertificateAssociationData());
    }
  }

  @Test
  void emptyAssociationDataFromWire() {
    TLSARecord tlsaRecord = new TLSARecord();
    DNSInput in = new DNSInput(new byte[] {0, 0, 1});
    assertThrows(WireParseException.class, () -> tlsaRecord.rrFromWire(in));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "0 0 1",
        "0 0 1 CAFEBABEZ",
        "0 0 1 CAFEBABEZ-",
        "0 0 1 A",
        "3 1 1 0D6FCE13243AA-"
      })
  void invalidRdataFromString(String rdata) {
    try (Tokenizer t = new Tokenizer(rdata)) {
      TLSARecord tlsaRecord = new TLSARecord();
      assertThrows(TextParseException.class, () -> tlsaRecord.rdataFromString(t, null));
    }
  }

  @Test
  void emptyAssociationDataConstruction() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new TLSARecord(Name.root, DClass.IN, 3600, 0, 0, 1, new byte[0]));
  }

  @Test
  void nullAssociationDataConstruction() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new TLSARecord(Name.root, DClass.IN, 3600, 0, 0, 1, null));
  }
}
