package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;

class MasterTest {

	@Test
	void nextRecord() throws IOException {
		Name exampleComName = Name.fromConstantString("example.com.");
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx1"))) {
			master.expandGenerate(false);
			Record rr = master.nextRecord();
			assertEquals(Type.SOA, rr.getType());
			rr = master.nextRecord();
			assertEquals(Type.NS, rr.getType());
			rr = master.nextRecord();
			assertEquals(Type.MX, rr.getType());

			rr = master.nextRecord();
			// test special '@' resolves name correctly
			assertEquals(exampleComName, rr.getName());

			rr = master.nextRecord();
			// test relative host become absolute
			assertEquals(Name.fromConstantString("mail3.example.com."), rr.getAdditionalName());

			rr = master.nextRecord();
			assertEquals(Type.A, rr.getType());

			rr = master.nextRecord();
			assertEquals(Type.AAAA, rr.getType());

			rr = master.nextRecord();
			assertEquals(Type.CNAME, rr.getType());

			rr = master.nextRecord();
			assertNull(rr);
			// $GENERATE directive is last in zonefile
			assertTrue(master.generators().hasNext());
		}
	}

	@Test
	void invalidGenRange() {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileInvalidGenRange"))) {
			assertThrows(TextParseException.class, master::nextRecord);
		}
	}

	@Test
	void invalidGenType() {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileInvalidGenType"))) {
			assertThrows(TextParseException.class, master::nextRecord);
		}
	}

	@Test
	void invalidTSIG() {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileInvalidTSIG"))) {
			assertThrows(TextParseException.class, master::nextRecord);
		}
	}

	@Test
	void invalidOriginNotAbsolute() {
		assertThrows(RelativeNameException.class, () ->
			new Master((InputStream) null, Name.fromConstantString("notabsolute")));
	}
}
