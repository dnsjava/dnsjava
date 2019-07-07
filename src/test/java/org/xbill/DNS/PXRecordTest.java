package org.xbill.DNS;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class PXRecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("10   net2.it.  PRMD-net2.ADMD-p400.C-it.");
		PXRecord record = new PXRecord();
		record.rdataFromString(t, null);
		assertEquals(10, record.getPreference());
		assertEquals(Name.fromConstantString("net2.it."), record.getMap822());
		assertEquals(Name.fromConstantString("PRMD-net2.ADMD-p400.C-it."), record.getMapX400());
	}
}
