// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;

class TestPositive extends TestBase {
  @Test
  void testValidExising() throws IOException {
    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals(localhost, firstA(response));
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testValidNonExising() throws IOException {
    Message response = resolver.send(createMessage("ingotronic.ch./ANY"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testValidAnswerToDifferentQueryTypeIsBogus() throws IOException {
    Message m = resolver.send(createMessage("www.ingotronic.ch./A"));
    Message message = createMessage("www.ingotronic.ch./MX");
    for (int i = 1; i < Section.ADDITIONAL; i++) {
      for (Record r : m.getSection(i)) {
        message.addRecord(r, i);
      }
    }

    add("www.ingotronic.ch./A", message);
    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("validate.response.unknown:UNKNOWN", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testCDonQueryDoesntDoAnything() throws IOException {
    Message m = resolver.send(createMessage("www.ingotronic.ch./A"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\s+A\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("www.ingotronic.ch./A", message);

    Message query = createMessage("www.ingotronic.ch./A");
    query.getHeader().setFlag(Flags.CD);
    Message response = resolver.send(query);
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }
}
