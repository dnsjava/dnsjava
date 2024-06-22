// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Section;

class TestCNames extends TestBase {
  @Test
  void testCNameToUnsignedA() throws IOException {
    Message response = resolver.send(createMessage("cunsinged.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals(3, response.getSection(Section.ANSWER).size());
    assertEquals("insecure.ds.nsec3", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToUnsignedMX() throws IOException {
    Message response = resolver.send(createMessage("cunsinged.ingotronic.ch./MX"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals(2, response.getSection(Section.ANSWER).size());
    assertEquals("insecure.ds.nsec3", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToSignedA() throws IOException {
    Message response = resolver.send(createMessage("csigned.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals(4, response.getSection(Section.ANSWER).size());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToSignedMX() throws IOException {
    Message response = resolver.send(createMessage("csigned.ingotronic.ch./MX"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals(2, response.getSection(Section.ANSWER).size());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToSignedAExternal() throws IOException {
    Message response = resolver.send(createMessage("csext.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals(4, response.getSection(Section.ANSWER).size());
    assertEquals(5, response.getSection(Section.AUTHORITY).size());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToInvalidSigned() throws IOException {
    Message response = resolver.send(createMessage("cfailed.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "validate.bogus.badkey:dnssec-failed.org.:dnskey.no_ds_alg_match:dnssec-failed.org.:RSASHA1",
        getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSKEY_MISSING, response);
  }

  @Test
  void testCNameToUnsignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("cunsinged.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToSignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("csigned.nsec3.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToInvalidSignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("cfailed.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "validate.bogus.badkey:dnssec-failed.org.:dnskey.no_ds_alg_match:dnssec-failed.org.:RSASHA1",
        getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSKEY_MISSING, response);
  }

  @ParameterizedTest(name = "testCNameToVoid_{index}")
  @CsvSource({"cvoid1,2", "cvoid2,4", "cvoid3,6"})
  void testCNameToVoid(String subdomain, int acount) throws IOException {
    Message response = resolver.send(createMessage(subdomain + ".ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertEquals(acount, response.getSection(Section.ANSWER).size());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToUnsignedVoid() throws IOException {
    Message response = resolver.send(createMessage("cvoid4.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertEquals("insecure.ds.nsec", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToExternalUnsignedVoid() throws IOException {
    Message response = resolver.send(createMessage("cvoid.dnssectest.jitsi.net./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertEquals("insecure.ds.nsec3", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToSubSigned() throws IOException {
    Message response = resolver.send(createMessage("cssub.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToVoidExternalInvalidTld() throws IOException {
    Message response = resolver.send(createMessage("cvoidext1.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertEquals(2, response.getSection(Section.ANSWER).size());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToVoidExternalValidTld() throws IOException {
    Message response = resolver.send(createMessage("cvoidext2.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testCNameToVoidNsec3() throws IOException {
    Message response = resolver.send(createMessage("cvoid.nsec3.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }
}
