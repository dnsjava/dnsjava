// SPDX-License-Identifier: BSD-3-Clause
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
    WKSRecord wksRecord = new WKSRecord();
    wksRecord.rdataFromString(t, null);
    assertNotNull(wksRecord.getAddress());
    assertEquals(WKSRecord.Protocol.TCP, wksRecord.getProtocol());
    assertArrayEquals(
        new int[] {WKSRecord.Service.FTP, WKSRecord.Service.TELNET, WKSRecord.Service.SMTP},
        wksRecord.getServices());
  }
}
