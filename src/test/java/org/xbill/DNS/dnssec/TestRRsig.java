// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

class TestRRsig extends TestBase {
  @Test
  void testRRsigNodata() throws IOException {
    Message message = createMessage("www.ingotronic.ch./RRSIG");
    add("www.ingotronic.ch./RRSIG", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./RRSIG"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
  }

  @Test
  void testRRsigServfail() throws IOException {
    Message message = createMessage("www.ingotronic.ch./RRSIG");
    message.getHeader().setRcode(Rcode.SERVFAIL);
    add("www.ingotronic.ch./RRSIG", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./RRSIG"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
  }
}
