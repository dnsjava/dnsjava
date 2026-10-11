// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class WKSRecordTest {
  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("127.0.0.1 tcp ftp telnet smtp");
    WKSRecord wks = new WKSRecord();
    wks.rdataFromString(t, null);
    assertThat(wks.getAddress().getAddress()).isEqualTo(new byte[] {127, 0, 0, 1});
    assertThat(wks.getProtocol()).isEqualTo(WKSRecord.Protocol.TCP);
    assertThat(wks.getServices())
        .containsExactly(WKSRecord.Service.FTP, WKSRecord.Service.TELNET, WKSRecord.Service.SMTP);
  }

  @Test
  void rdataUnsorted() throws IOException {
    Tokenizer t = new Tokenizer("192.0.2.1 6 80 25");
    WKSRecord wks = new WKSRecord();
    wks.rdataFromString(t, null);
    assertThat(wks.getAddress().getAddress()).isEqualTo(new byte[] {(byte) 192, 0, 2, 1});
    assertThat(wks.getProtocol()).isEqualTo(WKSRecord.Protocol.TCP);
    assertThat(wks.getServices()).containsExactly(WKSRecord.Service.SMTP, 80);

    DNSOutput out = new DNSOutput();
    wks.rrToWire(out, null, false);
    WKSRecord wks2 = new WKSRecord();
    wks2.rrFromWire(new DNSInput(out.toByteArray()));
    assertThat(wks2.getAddress().getAddress()).isEqualTo(new byte[] {(byte) 192, 0, 2, 1});
    assertThat(wks2.getProtocol()).isEqualTo(WKSRecord.Protocol.TCP);
    assertThat(wks2.getServices()).containsExactly(WKSRecord.Service.SMTP, 80);
  }
}
