package org.xbill.DNS;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class WKSRecordTest {

	@Test
	void rdataFromString() throws IOException {
		Tokenizer t = new Tokenizer("127.0.0.1 tcp ftp telnet smtp");
		WKSRecord record = new WKSRecord();
		record.rdataFromString(t, null);
		assertNotNull(record.getAddress());
		assertEquals(WKSRecord.Protocol.TCP, record.getProtocol());
		assertArrayEquals(new int[]{
			WKSRecord.Service.FTP,
			WKSRecord.Service.TELNET,
			WKSRecord.Service.SMTP}, record.getServices());
	}
}
