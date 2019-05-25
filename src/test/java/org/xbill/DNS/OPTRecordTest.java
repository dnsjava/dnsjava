package org.xbill.DNS;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class OPTRecordTest {

	private static final int DEFAULT_EDNS_RCODE = 0;
	private static final int DEFAULT_EDNS_VERSION = 0;
	private static final int DEFAULT_PAYLOAD_SIZE = 1024;

    @Test
	public void testForNoEqualityWithDifferentEDNS_Versions() {
		final OPTRecord optRecordOne = new OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, 0);
		final OPTRecord optRecordTwo = new OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, 1);
		assertNotEqual(optRecordOne, optRecordTwo);
	}

    @Test
	public void testForNoEqualityWithDifferentEDNS_RCodes() {
		final OPTRecord optRecordOne = new OPTRecord(DEFAULT_PAYLOAD_SIZE, 0, DEFAULT_EDNS_VERSION);
		final OPTRecord optRecordTwo = new OPTRecord(DEFAULT_PAYLOAD_SIZE, 1, DEFAULT_EDNS_VERSION);
		assertNotEqual(optRecordOne, optRecordTwo);
	}

    @Test
	public void testForEquality() {
		final OPTRecord optRecordOne = new OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, DEFAULT_EDNS_VERSION);
		final OPTRecord optRecordTwo = new OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, DEFAULT_EDNS_VERSION);
		assertEquals(optRecordOne, optRecordTwo);
		assertEquals(optRecordTwo, optRecordOne);
	}

	private void assertNotEqual(final OPTRecord optRecordOne, final OPTRecord optRecordTwo) {
		assertTrue("Expecting no equality of " + optRecordOne + " compared to " + optRecordTwo,
		    !optRecordOne.equals(optRecordTwo));
		assertTrue("Expecting no equality of " + optRecordTwo + " compared to " + optRecordOne,
		    !optRecordTwo.equals(optRecordOne));
	}

}
