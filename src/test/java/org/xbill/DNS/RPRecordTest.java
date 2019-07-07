package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class RPRecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("louie.trantor.umd.edu.  LAM1.people.umd.edu.");
		RPRecord record = new RPRecord();
		record.rdataFromString(t, null);
		assertEquals(Name.fromConstantString("louie.trantor.umd.edu."), record.getMailbox());
		assertEquals(Name.fromConstantString("LAM1.people.umd.edu."), record.getTextDomain());
	}
}
