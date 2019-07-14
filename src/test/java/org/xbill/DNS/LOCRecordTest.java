package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class LOCRecordTest {

	Name n = Name.fromConstantString("my.name.");

	@Test
	void ctor_0arg() {
		LOCRecord record = new LOCRecord();
		assertEquals(0.0, record.getVPrecision());
		assertEquals(0.0, record.getHPrecision());
		assertEquals(-100000.0, record.getAltitude());
		assertEquals(-596.52323, record.getLongitude(), 0.1);
		assertEquals(-596.52323, record.getLatitude(), 0.1);
		assertEquals(0.0, record.getSize());
	}

	@Test
	void ctor_9arg() {
		LOCRecord record = new LOCRecord(n, DClass.IN, 0, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5);
		assertEquals(6.5, record.getVPrecision());
		assertEquals(5.5, record.getHPrecision());
		assertEquals(3.5, record.getAltitude());
		assertEquals(2.5, record.getLongitude());
		assertEquals(1.5, record.getLatitude());
		assertEquals(4.5, record.getSize());
	}

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m");
		LOCRecord record = new LOCRecord();
		record.rdataFromString(t, null);
		assertEquals(10.0, record.getVPrecision());
		assertEquals(10000.0, record.getHPrecision());
		assertEquals(-2.0, record.getAltitude());
		assertEquals(4.892, record.getLongitude(), 0.1);
		assertEquals(52.373, record.getLatitude(), 0.1);
		assertEquals(0.0, record.getSize());
	}
}
