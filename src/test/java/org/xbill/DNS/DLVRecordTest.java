package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class DLVRecordTest {

	Name n = Name.fromConstantString("my.name.");

	@Test
	void ctor_0arg() {
		DLVRecord record = new DLVRecord();
		assertEquals(0, record.getFootprint());
		assertEquals(0, record.getAlgorithm());
		assertEquals(0, record.getDigestID());
		assertNull(record.getDigest());
	}

	@Test
	void ctor_7arg() {
		DLVRecord record = new DLVRecord(n, DClass.IN, 0, 1, 2, 3, "".getBytes());
		assertEquals(1, record.getFootprint());
		assertEquals(2, record.getAlgorithm());
		assertEquals(3, record.getDigestID());
		assertEquals(0, record.getDigest().length);
	}

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("60485 5 1 CAFEBABE");
		DLVRecord record = new DLVRecord();
		record.rdataFromString(t, null);
		assertEquals(60485, record.getFootprint());
		assertEquals(5, record.getAlgorithm());
		assertEquals(1, record.getDigestID());
		assertEquals(4, record.getDigest().length);
	}
}
