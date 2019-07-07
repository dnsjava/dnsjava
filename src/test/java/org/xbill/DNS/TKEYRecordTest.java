package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class TKEYRecordTest {

	@Test
	void rdataFromString() throws IOException {
		TextParseException thrown = assertThrows(TextParseException.class, () -> new TKEYRecord().rdataFromString(new Tokenizer(" "), null));
		assertTrue(thrown.getMessage().contains("no text format defined for TKEY"));
	}
}
