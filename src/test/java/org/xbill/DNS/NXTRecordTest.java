package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class NXTRecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("medium.foo.tld. A MX SIG NXT");
		NXTRecord record = new NXTRecord();
		record.rdataFromString(t, null);
		assertEquals(Name.fromConstantString("medium.foo.tld."),
			record.getNext());
		assertNotNull(record.getBitmap());
	}
}
