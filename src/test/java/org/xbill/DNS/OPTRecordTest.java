// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.DNSSEC.Digest;
import org.xbill.DNS.EDNSOption.Code;

class OPTRecordTest {

  private static final int DEFAULT_EDNS_RCODE = 0;
  private static final int DEFAULT_EDNS_VERSION = 0;
  private static final int DEFAULT_PAYLOAD_SIZE = 1024;

  @Test
  void testForNoEqualityWithDifferentEDNS_Versions() {
    final OPTRecord optRecordOne = new OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, 0);
    final OPTRecord optRecordTwo = new OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, 1);
    assertNotEqual(optRecordOne, optRecordTwo);
  }

  @Test
  void testForNoEqualityWithDifferentEDNS_RCodes() {
    final OPTRecord optRecordOne = new OPTRecord(DEFAULT_PAYLOAD_SIZE, 0, DEFAULT_EDNS_VERSION);
    final OPTRecord optRecordTwo = new OPTRecord(DEFAULT_PAYLOAD_SIZE, 1, DEFAULT_EDNS_VERSION);
    assertNotEqual(optRecordOne, optRecordTwo);
  }

  @Test
  void testForEquality() {
    final OPTRecord optRecordOne =
        new OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, DEFAULT_EDNS_VERSION);
    final OPTRecord optRecordTwo =
        new OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, DEFAULT_EDNS_VERSION);
    assertEquals(optRecordOne, optRecordTwo);
    assertEquals(optRecordTwo, optRecordOne);
  }

  @Test
  void testToString() {
    try {
      Options.set("BINDTTL");
      OPTRecord optRecord = new OPTRecord(DEFAULT_PAYLOAD_SIZE, 0xFF, DEFAULT_EDNS_VERSION);
      assertEquals(
          ".\t\t\t\tOPT\t ; payload 1024, xrcode 255, version 0, flags 0", optRecord.toString());
    } finally {
      Options.unset("BINDTTL");
    }
  }

  @Test
  void testMessageToString() {
    OPTRecord optRecord =
        new OPTRecord(
            DEFAULT_PAYLOAD_SIZE,
            0xFF,
            DEFAULT_EDNS_VERSION,
            Flags.DO,
            new TcpKeepaliveOption(100),
            new DnssecAlgorithmOption(Code.DAU, Algorithm.ED25519, Algorithm.ED448),
            new DnssecAlgorithmOption(Code.DHU, Digest.SHA384),
            new DnssecAlgorithmOption(Code.N3U, NSEC3Record.Digest.SHA1));
    Message m = Message.newQuery(Record.newRecord(Name.root, Type.A, DClass.IN));
    m.addRecord(optRecord, Section.ADDITIONAL);
    assertTrue(m.toString().contains(";; OPT PSEUDOSECTION:"));
    assertTrue(m.toString().contains("DAU: [ED25519, ED448]"));
    assertTrue(m.toString().contains("DHU: [SHA-384]"));
    assertTrue(m.toString().contains("N3U: [SHA-1]"));
  }

  @Test
  void rdataFromString() {
    TextParseException thrown =
        assertThrows(
            TextParseException.class,
            () -> new OPTRecord().rdataFromString(new Tokenizer(" "), null));
    assertTrue(thrown.getMessage().contains("no text format defined for OPT"));
  }

  private void assertNotEqual(final OPTRecord optRecordOne, final OPTRecord optRecordTwo) {
    assertNotEquals(optRecordOne, optRecordTwo);
    assertNotEquals(optRecordTwo, optRecordOne);
  }
}
