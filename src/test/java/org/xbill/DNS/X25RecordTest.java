package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class X25RecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("311061700956");
		X25Record record = new X25Record();
		record.rdataFromString(t, null);
		assertEquals("311061700956", record.getAddress());
	}
}
