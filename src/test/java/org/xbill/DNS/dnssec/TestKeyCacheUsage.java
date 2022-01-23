// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

class TestKeyCacheUsage extends TestBase {

  @Test
  void testUnsigned() throws IOException {
    Message response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals(localhost, firstA(response));
    assertEquals("insecure.ds.nsec", getReason(response));
    assertEde(-1, response);

    // send the query a second time to ensure the cache doesn't create a wrong behavior
    response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals(localhost, firstA(response));
    assertEquals("insecure.ds.nsec", getReason(response));
    assertEde(-1, response);
  }
}
