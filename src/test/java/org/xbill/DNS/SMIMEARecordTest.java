// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

class SMIMEARecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("(3 0 2 CAFEBABE)");
    SMIMEARecord smimeaRecord = new SMIMEARecord();
    smimeaRecord.rdataFromString(t, null);
    assertThat(smimeaRecord.getCertificateUsage())
        .isEqualTo(SMIMEARecord.CertificateUsage.DOMAIN_ISSUED_CERTIFICATE);
    assertThat(smimeaRecord.getMatchingType()).isEqualTo(SMIMEARecord.MatchingType.SHA512);
    assertThat(smimeaRecord.getSelector()).isEqualTo(SMIMEARecord.Selector.FULL_CERTIFICATE);
    assertThat(smimeaRecord.getCertificateAssociationData())
        .containsExactly(base16.fromString("CAFEBABE"));
  }
}
