package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

class TLSARecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("(0 0 1 CAFEBABE)");
    TLSARecord record = new TLSARecord();
    record.rdataFromString(t, null);
    assertEquals(TLSARecord.CertificateUsage.CA_CONSTRAINT, record.getCertificateUsage());
    assertEquals(TLSARecord.MatchingType.SHA256, record.getMatchingType());
    assertEquals(TLSARecord.Selector.FULL_CERTIFICATE, record.getSelector());
    assertArrayEquals(base16.fromString("CAFEBABE"), record.getCertificateAssociationData());
  }
}
