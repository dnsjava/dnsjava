package org.xbill.DNS;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class SSHFPRecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("2 1 CAFEBABE");
		SSHFPRecord record = new SSHFPRecord();
		record.rdataFromString(t, null);
		assertEquals(SSHFPRecord.Algorithm.DSS, record.getAlgorithm());
		assertEquals(SSHFPRecord.Digest.SHA1, record.getDigestType());
		assertArrayEquals(base16.fromString("CAFEBABE"), record.getFingerPrint());
	}
}
