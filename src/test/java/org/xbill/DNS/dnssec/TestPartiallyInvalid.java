// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

class TestPartiallyInvalid extends TestBase {
  @Test
  void testValidExising() throws IOException {
    Message response = resolver.send(createMessage("www.partial.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals(localhost, firstA(response));
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testValidExisingNoType() throws IOException {
    Message response = resolver.send(createMessage("www.partial.ingotronic.ch./MX"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertTrue(isEmptyAnswer(response));
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testValidNonExising() throws IOException {
    Message response = resolver.send(createMessage("www.gibtsnicht.partial.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }
}
