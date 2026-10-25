// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
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
    DnsSecVerifier verifier = new DnsSecVerifier(new ValUtils());
    ARecord aRecord = new ARecord(Name.root, DClass.IN, 120, localhost);
    SRRset set = new SRRset();
    set.addRR(aRecord);
    KeyEntry keys = KeyEntry.newKeyEntry(new SRRset());
    JustifiedSecStatus res = verifier.verify(set, keys, Instant.now());
    assertThat(res.status).isEqualTo(SecurityStatus.BOGUS);
    assertThat(res.edeReason).isEqualTo(ExtendedErrorCodeOption.RRSIGS_MISSING);
  }

  @Test
  void useAllEnumCode() {
    assertThat(SecurityStatus.valueOf(SecurityStatus.values()[0].toString()))
        .isEqualTo(SecurityStatus.UNCHECKED);
    assertThat(ResponseClassification.valueOf(ResponseClassification.values()[0].toString()))
        .isEqualTo(ResponseClassification.UNKNOWN);
  }

  @Test
  void testSmessageReturnsOptRecordOfOriginal() {
    int xrcode = 0xFED;
    Message m = Message.newQuery(Record.newRecord(Name.root, Type.NS, DClass.IN));
    m.getHeader().setRcode(xrcode & 0xF);
    m.addRecord(new OPTRecord(1, xrcode >> 4, 1), Section.ADDITIONAL);
    SMessage sm = new SMessage(m);
    assertThat(sm.getMessage()).hasToString(m.toString());
    assertThat(sm.getRcode()).isEqualTo(xrcode);
  }

  @Test
  void testCopyMessageWithoutQuestion() {
    Message m = new Message();
    m.addRecord(new ARecord(Name.root, DClass.IN, 120, localhost), Section.ANSWER);
    SMessage sm = new SMessage(m);
    assertThat(sm.getMessage()).hasToString(m.toString());
  }
}
