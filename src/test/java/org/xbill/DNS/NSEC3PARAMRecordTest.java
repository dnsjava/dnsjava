package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class NSEC3PARAMRecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("1 1 10 5053851B");
		NSEC3PARAMRecord record = new NSEC3PARAMRecord();
		record.rdataFromString(t, null);
		assertEquals(NSEC3Record.Digest.SHA1, record.getHashAlgorithm());
		assertEquals(NSEC3Record.Flags.OPT_OUT, record.getFlags());
		assertNotNull(record.getSalt());
	}
}
