// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

class TestNoData extends TestBase {
  @Test
  void testFakedNoDataNsec3WithoutNsecs() throws IOException {
    Message m = resolver.send(createMessage("www.nsec3.ingotronic.ch./A"));
    Message message =
        messageFromString(m.toString().replaceAll("www\\.nsec3\\.ingotronic\\.ch\\.\\s+.*", ""));
    add("www.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.nodata"));
    assertEde(ExtendedErrorCodeOption.NSEC_MISSING, response);
  }

  @Test
  void testFakedNoDataNsec3WithNsecs() throws IOException {
    Message m = resolver.send(createMessage("www.nsec3.ingotronic.ch./MX"));
    Message message = messageFromString(m.toString().replaceAll("type = MX", "type = A"));
    add("www.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.nodata"));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }
}
