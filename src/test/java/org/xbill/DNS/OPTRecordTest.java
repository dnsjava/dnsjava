// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

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
  void rdataFromString() {
    TextParseException thrown =
        assertThrows(
            TextParseException.class,
            () -> new OPTRecord().rdataFromString(new Tokenizer(" "), null));
    assertTrue(thrown.getMessage().contains("no text format defined for OPT"));
  }

  @Test
  void rdataFromWire() throws IOException {
    byte[] buf = base16.fromString("000029100000000000000C000A00084531D089BA80C6EB");
    OPTRecord record = (OPTRecord) OPTRecord.fromWire(new DNSInput(buf), Section.ADDITIONAL);
    assertEquals(
        Collections.singletonList(new CookieOption(base16.fromString("4531D089BA80C6EB"))),
        record.getOptions());
  }

  @Test
  void rdataFromWire_nullPadded() throws IOException {
    byte[] buf = base16.fromString("000029100000000000000C000A00084531D089BA80C6EB00");
    OPTRecord record = (OPTRecord) OPTRecord.fromWire(new DNSInput(buf), Section.ADDITIONAL);
    assertEquals(
        Collections.singletonList(new CookieOption(base16.fromString("4531D089BA80C6EB"))),
        record.getOptions());
  }

  private void assertNotEqual(final OPTRecord optRecordOne, final OPTRecord optRecordTwo) {
    assertFalse(optRecordOne.equals(optRecordTwo));
    assertFalse(optRecordTwo.equals(optRecordOne));
  }
}
