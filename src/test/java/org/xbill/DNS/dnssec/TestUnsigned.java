// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

class TestUnsigned extends TestBase {
  @Test
  void testUnsignedBelowSignedZoneBind() throws IOException {
    Message response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals(localhost, firstA(response));
    assertEquals("insecure.ds.nsec", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testUnsignedBelowSignedTldNsec3NoOptOut() throws IOException {
    Message response = resolver.send(createMessage("20min.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testUnsignedBelowSignedTldNsec3OptOut() throws IOException {
    Message response = resolver.send(createMessage("yahoo.com./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testUnsignedBelowUnsignedZone() throws IOException {
    Message response = resolver.send(createMessage("www.sub.unsigned.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals(localhost, firstA(response));
    assertEquals("insecure.ds.nsec", getReason(response));
    assertEde(-1, response);
  }
}
