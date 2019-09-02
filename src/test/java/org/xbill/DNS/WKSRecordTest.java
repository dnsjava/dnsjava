package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class WKSRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("127.0.0.1 tcp ftp telnet smtp");
    WKSRecord record = new WKSRecord();
    record.rdataFromString(t, null);
    assertNotNull(record.getAddress());
    assertEquals(WKSRecord.Protocol.TCP, record.getProtocol());
    assertArrayEquals(
        new int[] {WKSRecord.Service.FTP, WKSRecord.Service.TELNET, WKSRecord.Service.SMTP},
        record.getServices());
  }
}
