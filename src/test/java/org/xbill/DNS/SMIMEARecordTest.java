package org.xbill.DNS;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class SMIMEARecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("(3 0 2 CAFEBABE)");
		SMIMEARecord record = new SMIMEARecord();
		record.rdataFromString(t, null);
		assertEquals(SMIMEARecord.CertificateUsage.DOMAIN_ISSUED_CERTIFICATE, record.getCertificateUsage());
		assertEquals(SMIMEARecord.MatchingType.SHA512, record.getMatchingType());
		assertEquals(SMIMEARecord.Selector.FULL_CERTIFICATE, record.getSelector());
		assertArrayEquals(base16.fromString("CAFEBABE"), record.getCertificateAssociationData());
	}
}
