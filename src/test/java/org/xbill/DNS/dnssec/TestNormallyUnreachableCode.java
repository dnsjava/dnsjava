// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

/**
 * These test run checks that are unable to occur during actual validations.
 *
 * @author Ingo Bauersachs
 */
class TestNormallyUnreachableCode {
  private InetAddress localhost;

  @BeforeEach
  void setUp() throws UnknownHostException {
    localhost = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
  }

  @Test
  void testVerifyWithoutSignaturesIsBogus() {
    DnsSecVerifier verifier = new DnsSecVerifier();
    ARecord record = new ARecord(Name.root, DClass.IN, 120, localhost);
    SRRset set = new SRRset();
    set.addRR(record);
    RRset keys = new RRset();
    SecurityStatus result = verifier.verify(set, keys, Instant.now());
    assertEquals(SecurityStatus.BOGUS, result);
  }

  @Test
  void useAllEnumCode() {
    assertEquals(
        SecurityStatus.UNCHECKED, SecurityStatus.valueOf(SecurityStatus.values()[0].toString()));
    assertEquals(
        ResponseClassification.UNKNOWN,
        ResponseClassification.valueOf(ResponseClassification.values()[0].toString()));
  }

  @Test
  void testSmessageReturnsOptRecordOfOriginal() {
    int xrcode = 0xFED;
    Message m = Message.newQuery(Record.newRecord(Name.root, Type.NS, DClass.IN));
    m.getHeader().setRcode(xrcode & 0xF);
    m.addRecord(new OPTRecord(1, xrcode >> 4, 1), Section.ADDITIONAL);
    SMessage sm = new SMessage(m);
    assertEquals(m.toString(), sm.getMessage().toString());
    assertEquals(xrcode, sm.getRcode());
  }

  @Test
  void testCopyMessageWithoutQuestion() {
    Message m = new Message();
    m.addRecord(new ARecord(Name.root, DClass.IN, 120, localhost), Section.ANSWER);
    SMessage sm = new SMessage(m);
    assertEquals(m.toString(), sm.getMessage().toString());
  }
}
