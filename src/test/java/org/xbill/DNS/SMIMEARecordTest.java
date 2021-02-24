// SPDX-License-Identifier: BSD-2-Clause
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
    SMIMEARecord record = new SMIMEARecord();
    record.rdataFromString(t, null);
    assertEquals(
        SMIMEARecord.CertificateUsage.DOMAIN_ISSUED_CERTIFICATE, record.getCertificateUsage());
    assertEquals(SMIMEARecord.MatchingType.SHA512, record.getMatchingType());
    assertEquals(SMIMEARecord.Selector.FULL_CERTIFICATE, record.getSelector());
    assertArrayEquals(base16.fromString("CAFEBABE"), record.getCertificateAssociationData());
  }
}
