// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Section;

class TestNonExistence extends TestBase {
  @ParameterizedTest(name = "testNonExisting_{index}")
  @ValueSource(
      strings = {
        "gibtsnicht",
        "gibtsnicht.ingotronic.ch",
        "gibtsnicht.nsec3.ingotronic.ch",
        "gibtsnicht.gibtsnicht.ingotronic.ch",
        "gibtsnicht.gibtsnicht.nsec3.ingotronic.ch"
      })
  void testNonExisting(String param) throws IOException {
    Message response = resolver.send(createMessage(param + "./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
    assertEquals(-1, getEdeReason(response));
  }

  @Test
  void testDoubleLabelABelowSignedNsec3MissingNsec3() throws IOException {
    Message m = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
    Message message =
        messageFromString(m.toString().replaceAll("L40.+nsec3\\.ingotronic\\.ch\\.\\s+300.*", ""));
    add("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nxdomain.nsec3_bogus", getReason(response));
    assertEquals(ExtendedErrorCodeOption.DNSSEC_BOGUS, getEdeReason(response));
  }

  @Test
  void testDoubleLabelABelowSignedBeforeZoneNsec3() throws IOException {
    // the query name here must hash to a name BEFORE the first existing
    // NSEC3 owner name
    Message response = resolver.send(createMessage("alias.1gibtsnicht.nsec3.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
    assertEquals(-1, getEdeReason(response));
  }

  @ParameterizedTest(name = "testSignedNodata_{index}")
  @ValueSource(
      strings = {
        "www.ingotronic.ch",
        "www.nsec3.ingotronic.ch",
        "a.b.ingotronic.ch",
        "a.b.nsec3.ingotronic.ch",
        "b.d.ingotronic.ch",
        "b.d.nsec3.ingotronic.ch",
      })
  void testSignedNodata(String param) throws IOException {
    Message response = resolver.send(createMessage(param + "./MX"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertTrue(response.getSectionRRsets(Section.ANSWER).isEmpty());
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEquals(-1, getEdeReason(response));
  }

  @Test
  void testNxDomainWithInvalidNsecSignature() throws IOException {
    Message m = resolver.send(createMessage("x.ingotronic.ch./A"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("x.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("x.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.nxdomain.authority"));
    assertEquals(ExtendedErrorCodeOption.DNSSEC_BOGUS, getEdeReason(response));
  }

  @Test
  void testNoDataWithInvalidNsecSignature() throws IOException {
    Message m = resolver.send(createMessage("www.ingotronic.ch./MX"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("www.ingotronic.ch./MX", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./MX"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.authority.nodata"));
    assertEquals(ExtendedErrorCodeOption.DNSSEC_BOGUS, getEdeReason(response));
  }

  @Test
  void testNoDataOnENT() throws IOException {
    Message response = resolver.send(createMessage("b.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertEquals(Rcode.NOERROR, response.getRcode());
    assertEquals(-1, getEdeReason(response));
  }
}
