// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

class TestValUtils extends TestBase {
  @Test
  void testLongestCommonNameRootIsRoot() {
    assertEquals(
        Name.root,
        ValUtils.longestCommonName(
            Name.fromConstantString("example.com."), Name.fromConstantString("example.net.")));
  }

  @Test
  void testNoDataWhenResultIsFromDelegationPoint() throws IOException {
    Message nsec = resolver.send(createMessage("t.ingotronic.ch./A"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.AUTHORITY)) {
      if (set.getName().toString().startsWith("sub.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = resolver.send(createMessage("sub.ingotronic.ch./MX"));
    Message message =
        messageFromString(m.toString().replaceAll("sub\\.ingotronic\\.ch\\.\\s+\\d+.*", ""));
    message.addRecord(delegationNsec, Section.AUTHORITY);
    message.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("sub.ingotronic.ch./MX", message);

    Message response = resolver.send(createMessage("sub.ingotronic.ch./MX"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNameErrorWhenResultIsFromDelegationPoint() throws IOException {
    Message nsec = resolver.send(createMessage("sub1.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.AUTHORITY)) {
      if (set.getName().toString().startsWith("sub.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("s.sub.ingotronic.ch./A");
    m.getHeader().setRcode(Rcode.NXDOMAIN);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("s.sub.ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("s.sub.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nxdomain.exists:s.sub.ingotronic.ch.", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNameErrorWhenNsecIsNotFromApex() throws IOException {
    Message response = resolver.send(createMessage("1.www.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertNull(getReason(response));
  }

  @Test
  void testNameErrorWhenNsecIsLastAndQnameBefore() throws IOException {
    Message nsec = resolver.send(createMessage("zz.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.AUTHORITY)) {
      if (set.getName().toString().startsWith("z.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("y.ingotronic.ch./A");
    m.getHeader().setRcode(Rcode.NXDOMAIN);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("y.ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("y.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nxdomain.exists:y.ingotronic.ch.", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNameErrorWhenNsecIsLastAndQnameDifferentDomain() throws IOException {
    Message nsec = resolver.send(createMessage("zz.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.AUTHORITY)) {
      if (set.getName().toString().startsWith("z.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("zingotronic.ch./A");
    m.getHeader().setRcode(Rcode.NXDOMAIN);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("zingotronic.ch./A", m);

    Message response = resolver.send(createMessage("zingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nxdomain.exists:zingotronic.ch.", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNameErrorWhenNsecIsLastAndQnameIsZoneApex() throws IOException {
    Message nsec = resolver.send(createMessage("zz.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.AUTHORITY)) {
      if (set.getName().toString().startsWith("z.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("ingotronic.ch./A");
    m.getHeader().setRcode(Rcode.NXDOMAIN);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nxdomain.exists:ingotronic.ch.", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNoDataWhenDSResultIsFromChild() throws IOException {
    Message m = resolver.send(createMessage("samekey.ingotronic.ch./MX"));
    // this test needs to have the key in the cache
    add("samekey.ingotronic.ch./DS", m, false);

    Message response = resolver.send(createMessage("samekey.ingotronic.ch./DS"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNoDataOfDSForRoot() throws IOException {
    Message response = resolver.send(createMessage("./DS"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testNsecProvesNoDS() {
    SecurityStatus s =
        ValUtils.nsecProvesNoDS(
            new NSECRecord(Name.root, DClass.IN, 0, Name.root, new int[] {Type.SOA, Type.NS}),
            Name.root);
    assertEquals(SecurityStatus.SECURE, s, "Root NSEC SOA and without DS must be secure");
  }

  @Test
  void testNsecProvesNoDSWithDSPresentForRoot() {
    SecurityStatus s =
        ValUtils.nsecProvesNoDS(
            new NSECRecord(
                Name.root, DClass.IN, 0, Name.root, new int[] {Type.SOA, Type.NS, Type.DS}),
            Name.root);
    assertEquals(SecurityStatus.BOGUS, s, "Root NSEC with DS must be bogus");
  }

  @Test
  void testNsecProvesNoDSWithSOAForNonRoot() throws IOException {
    Name ch = Name.fromString("ch.");
    SecurityStatus s =
        ValUtils.nsecProvesNoDS(
            new NSECRecord(ch, DClass.IN, 0, ch, new int[] {Type.SOA, Type.NS}), ch);
    assertEquals(SecurityStatus.BOGUS, s, "Non-root NSEC with SOA must be bogus");
  }

  @Test
  void testNoDataOnEntWithWrongNsec() throws IOException {
    Message nsec = resolver.send(createMessage("alias.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.ANSWER)) {
      if (set.getName().toString().startsWith("alias.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("ingotronic.ch./A");
    m.getHeader().setRcode(Rcode.NOERROR);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNoDataWhenNsecProvesExistence() throws IOException {
    Message nsec = resolver.send(createMessage("www.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.ANSWER)) {
      if (set.getName().toString().startsWith("www.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("www.ingotronic.ch./AAAA");
    m.getHeader().setRcode(Rcode.NOERROR);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("www.ingotronic.ch./AAAA", m);

    Message response = resolver.send(createMessage("www.ingotronic.ch./AAAA"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNoDataWhenNsecHasCname() throws IOException {
    Message nsec = resolver.send(createMessage("csigned.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.ANSWER)) {
      if (set.getName().toString().startsWith("csigned.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("csigned.ingotronic.ch./A");
    m.getHeader().setRcode(Rcode.NOERROR);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("csigned.ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("csigned.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNoDataWhenWcNsecProvesType() throws IOException {
    Message nsec = resolver.send(createMessage("*.c.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.ANSWER)) {
      if (set.getName().toString().startsWith("*.c.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("a.c.ingotronic.ch./A");
    m.getHeader().setRcode(Rcode.NOERROR);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("a.c.ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("a.c.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNoDataWhenWcNsecProvesCname() throws IOException {
    Message nsec = resolver.send(createMessage("*.cwv.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.ANSWER)) {
      if (set.getName().toString().startsWith("*.cwv.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("a.cwv.ingotronic.ch./A");
    m.getHeader().setRcode(Rcode.NOERROR);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("a.cwv.ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("a.cwv.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNoDataWhenWcNsecIsForDifferentName() throws IOException {
    Message nsec = resolver.send(createMessage("*.c.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.ANSWER)) {
      if (set.getName().toString().startsWith("*.c.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("b.d.ingotronic.ch./A");
    m.getHeader().setRcode(Rcode.NOERROR);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("b.d.ingotronic.ch./A", m);

    Message response = resolver.send(createMessage("b.d.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nodata", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testDsNoDataWhenNsecProvesDs() throws IOException {
    Message nsec = resolver.send(createMessage("sub1.ingotronic.ch./NSEC"));
    Record delegationNsec = null;
    Record delegationNsecSig = null;
    for (RRset set : nsec.getSectionRRsets(Section.AUTHORITY)) {
      if (set.getName().toString().startsWith("sub.ingotronic.ch")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = createMessage("sub.ingotronic.ch./DS");
    m.getHeader().setRcode(Rcode.NOERROR);
    m.addRecord(delegationNsec, Section.AUTHORITY);
    m.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("sub.ingotronic.ch./DS", m);

    Message response = resolver.send(createMessage("sub.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "validate.bogus.badkey:sub.ingotronic.ch.:failed.ds.nsec.hasdata", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testHasSignedNsecsWithoutSignedSigsReturnsFalse() {
    Message m = new Message();
    m.addRecord(
        new NSECRecord(Name.root, DClass.IN, 0, Name.root, new int[] {Type.A}), Section.AUTHORITY);
    SMessage sm = new SMessage(m);
    boolean result = new ValUtils().hasSignedNsecs(sm);
    assertFalse(result);
  }
}
