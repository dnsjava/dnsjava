package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class SPFRecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("v=spf1 a mx ip4:69.64.153.131 include:_spf.google.com ~all");
		SPFRecord record = new SPFRecord();
		record.rdataFromString(t, null);
		assertEquals(6, record.getStrings().size());
		assertEquals(6, record.getStringsAsByteArrays().size());
	}
}
