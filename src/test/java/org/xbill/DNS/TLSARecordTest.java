// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

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
      assertThat(tlsaRecord.getCertificateUsage())
          .isEqualTo(TLSARecord.CertificateUsage.CA_CONSTRAINT);
      assertThat(tlsaRecord.getMatchingType()).isEqualTo(TLSARecord.MatchingType.SHA256);
      assertThat(tlsaRecord.getSelector()).isEqualTo(TLSARecord.Selector.FULL_CERTIFICATE);
      assertThat(tlsaRecord.getCertificateAssociationData())
          .containsExactly(base16.fromString(rdata));
    }
  }

  @Test
  void emptyAssociationDataFromWire() {
    TLSARecord tlsaRecord = new TLSARecord();
    DNSInput in = new DNSInput(new byte[] {0, 0, 1});
    assertThatExceptionOfType(WireParseException.class).isThrownBy(() -> tlsaRecord.rrFromWire(in));
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
      assertThatExceptionOfType(TextParseException.class)
          .isThrownBy(() -> tlsaRecord.rdataFromString(t, null));
    }
  }

  @Test
  void emptyAssociationDataConstruction() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TLSARecord(Name.root, DClass.IN, 3600, 0, 0, 1, new byte[0]));
  }

  @Test
  void nullAssociationDataConstruction() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TLSARecord(Name.root, DClass.IN, 3600, 0, 0, 1, null));
  }
}
