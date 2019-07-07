package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class NULLRecordTest {

	@Test
	void rdataFromString() throws IOException {
		TextParseException thrown = assertThrows(TextParseException.class, () -> new NULLRecord().rdataFromString(new Tokenizer(" "), null));
		assertTrue(thrown.getMessage().contains("no defined text format for NULL records"));
	}
}
