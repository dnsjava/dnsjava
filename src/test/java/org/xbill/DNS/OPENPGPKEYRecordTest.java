package org.xbill.DNS;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base64;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class OPENPGPKEYRecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("CAFEBABE");
		OPENPGPKEYRecord record = new OPENPGPKEYRecord();
		record.rdataFromString(t, null);
		assertArrayEquals(base64.fromString("CAFEBABE"), record.getCert());
	}
}
