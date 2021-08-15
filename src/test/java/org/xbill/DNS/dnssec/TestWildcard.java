// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

class TestWildcard extends TestBase {
  @Test
  void testNameNotExpandedFromWildcardWhenNonWildcardExists() throws IOException {
    // create a faked response: the original query/response was for
    // b.d.ingotronic.ch. and is changed to a.d.ingotronic.ch.
    Message m = resolver.send(createMessage("b.d.ingotronic.ch./A"));
    add(
        "a.d.ingotronic.ch./A",
        messageFromString(m.toString().replace("b.d.ingotronic.ch.", "a.d.ingotronic.ch.")));

    // a.d.ingotronic.ch./A exists, but the response is faked from *.d.ingotronic.ch. which must be
    // detected by the NSEC proof
    Message response = resolver.send(createMessage("a.d.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getHeader().getRcode());
    assertEquals("failed.positive.wildcard_too_broad", getReason(response));
  }

  @Test
  void testNameNotExpandedFromWildcardWhenNonWildcardExistsNsec3() throws IOException {
    // create a faked response: the original query/response was for
    // b.d.nsec3.ingotronic.ch. and is changed to a.d.nsec3.ingotronic.ch.
    Message m = resolver.send(createMessage("b.d.nsec3.ingotronic.ch./A"));
    add(
        "a.d.nsec3.ingotronic.ch./A",
        messageFromString(
            m.toString().replace("b.d.nsec3.ingotronic.ch.", "a.d.nsec3.ingotronic.ch.")));

    // a.d.nsec3.ingotronic.ch./A exists, but the response is faked from
    // *.d.nsec3.ingotronic.ch. which must be detected by the NSEC proof
    Message response = resolver.send(createMessage("a.d.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getHeader().getRcode());
    assertEquals("failed.positive.wildcard_too_broad", getReason(response));
  }

  @AlwaysOffline
  @Test
  void testLabelCountInSignaturesNotAllSame() throws IOException {
    Message response = resolver.send(createMessage("b.d.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD));
    assertEquals(Rcode.SERVFAIL, response.getHeader().getRcode());
    assertEquals(
        "failed.wildcard.label_count_mismatch:b.d.nsec3.ingotronic.ch.", getReason(response));
  }

  @Test
  void testSynthesisUsesCorrectWildcard() throws IOException {
    Message m = resolver.send(createMessage("a.wc.ingotronic.ch./A"));
    Message message =
        messageFromString(
            m.toString().replaceAll("a\\.wc\\.ingotronic.ch\\.", "\1.sub.wc.ingotronic.ch."));
    add(Name.fromString("\1.sub.wc.ingotronic.ch.").toString() + "/A", message);

    Message response = resolver.send(createMessage("\1.sub.wc.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.positive.wildcard_too_broad", getReason(response));
  }

  @Test
  void testPositiveWithInvalidNsecSignature() throws IOException {
    Message m = resolver.send(createMessage("a.c.ingotronic.ch./A"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("a.c.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("a.c.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.authority.positive"));
  }

  @Test
  void testNodataWilcardWithoutCe() throws IOException {
    // strip the closest encloser NSEC
    Message m = resolver.send(createMessage("\1.c.ingotronic.ch./MX"));
    Message message = messageFromString(m.toString().replaceAll("a\\.b\\.ingotronic\\.ch.*", ""));
    add(Name.fromString("\1.c.ingotronic.ch./MX").toString(), message);

    Message response = resolver.send(createMessage("\1.c.ingotronic.ch./MX"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
  }

  @Test
  void testSynthesisUsesCorrectWildcardNodata() throws IOException {
    Message m = resolver.send(createMessage("a.wc.ingotronic.ch./MX"));
    Message message =
        messageFromString(
            m.toString().replaceAll("a\\.wc\\.ingotronic.ch\\.", "\1.sub.wc.ingotronic.ch."));
    add(Name.fromString("\1.sub.wc.ingotronic.ch.").toString() + "/MX", message);

    Message response = resolver.send(createMessage("\1.sub.wc.ingotronic.ch./MX"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
  }

  @Test
  void testSynthesisUsesCorrectWildcardNodataNsec3() throws IOException {
    Message m = resolver.send(createMessage("a.wc.nsec3.ingotronic.ch./MX"));
    Message message =
        messageFromString(
            m.toString()
                .replaceAll("a\\.wc\\.nsec3.ingotronic.ch\\.", "\1.sub.wc.nsec3.ingotronic.ch."));
    add(Name.fromString("\1.sub.wc.nsec3.ingotronic.ch.").toString() + "/MX", message);

    Message response = resolver.send(createMessage("\1.sub.wc.nsec3.ingotronic.ch./MX"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
  }

  @Test
  void testDsNodataFromWildcardNsecChild() throws IOException {
    Message m =
        Message.newQuery(
            Record.newRecord(Name.fromString("www.x.c.ingotronic.ch."), Type.A, DClass.IN));
    m.addRecord(
        new ARecord(
            Name.fromString("www.x.c.ingotronic.ch."), DClass.IN, 300, InetAddress.getLocalHost()),
        Section.ANSWER);
    add("www.x.c.ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("www.x.c.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
  }

  @Test
  void testDsNodataFromWildcardNsecCovered() throws IOException {
    Message m =
        Message.newQuery(
            Record.newRecord(Name.fromString("www.x.ce.ingotronic.ch."), Type.A, DClass.IN));
    m.addRecord(
        new ARecord(
            Name.fromString("www.x.ce.ingotronic.ch."), DClass.IN, 300, InetAddress.getLocalHost()),
        Section.ANSWER);
    add("www.x.ce.ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("www.x.ce.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertEquals(Rcode.SERVFAIL, response.getRcode());
  }
}
