package org.xbill.DNS;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base64;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class NAPTRRecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("100  50  \"s\"    \"http+N2L+N2C+N2R\"  \"\"   www.example.com.");
		NAPTRRecord record = new NAPTRRecord();
		record.rdataFromString(t, null);
		assertEquals(100, record.getOrder());
		assertEquals(50, record.getPreference());
		assertEquals("s", record.getFlags());
		assertEquals("http+N2L+N2C+N2R", record.getService());
		assertEquals("", record.getRegexp());
		assertEquals(Name.fromConstantString("www.example.com."), record.getReplacement());
	}
}
