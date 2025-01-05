// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

class SMIMEARecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("(3 0 2 CAFEBABE)");
    SMIMEARecord smimeaRecord = new SMIMEARecord();
    smimeaRecord.rdataFromString(t, null);
    assertEquals(
        SMIMEARecord.CertificateUsage.DOMAIN_ISSUED_CERTIFICATE,
        smimeaRecord.getCertificateUsage());
    assertEquals(SMIMEARecord.MatchingType.SHA512, smimeaRecord.getMatchingType());
    assertEquals(SMIMEARecord.Selector.FULL_CERTIFICATE, smimeaRecord.getSelector());
    assertArrayEquals(base16.fromString("CAFEBABE"), smimeaRecord.getCertificateAssociationData());
  }
}
