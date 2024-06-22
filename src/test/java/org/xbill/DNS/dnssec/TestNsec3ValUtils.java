// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Properties;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;

class TestNsec3ValUtils extends TestBase {
  @Test
  void testTooLargeIterationCountMustThrow() {
    Properties config = new Properties();
    config.put("dnsjava.dnssec.nsec3.iterations.512", Integer.MAX_VALUE);
    NSEC3ValUtils val = new NSEC3ValUtils();
    assertThrows(IllegalArgumentException.class, () -> val.init(config));
  }

  @Test
  void testInvalidIterationCountMarksInsecure() throws IOException {
    Properties config = new Properties();
    config.put("dnsjava.dnssec.nsec3.iterations.1024", 0);
    config.put("dnsjava.dnssec.nsec3.iterations.2048", 0);
    config.put("dnsjava.dnssec.nsec3.iterations.4096", 0);
    resolver.init(config);

    Message response = resolver.send(createMessage("www.wc.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals("failed.nsec3_ignored", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testNsec3WithoutClosestEncloser() throws IOException {
    Message m = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
    Message message =
        messageFromString(
            m.toString()
                .replaceAll(
                    "((UDUMPS9J6F8348HFHH2FAED6I9DDE0U6)|(NTV3QJT4VQDVBPB6BNOVM40NMKJ3H29P))\\.nsec3.*",
                    ""));
    add("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nxdomain.nsec3_bogus", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNsec3NodataChangedToNxdomainIsBogus() throws IOException {
    Message m = resolver.send(createMessage("a.b.nsec3.ingotronic.ch./MX"));
    Message message =
        messageFromString(m.toString().replaceAll("status: NOERROR", "status: NXDOMAIN"));
    add("a.b.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("a.b.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nxdomain.nsec3_bogus", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNsec3ClosestEncloserIsDelegation() throws IOException {
    // hash(n=9.nsec3.ingotronic.ch.,it=10,s=1234)=6jl2t4i2bb7eilloi8mdhbf3uqjgvu4s
    Message cem = resolver.send(createMessage("9.nsec3.ingotronic.ch./A"));
    Record delegationNsec = null;
    RRSIGRecord delegationNsecSig = null;
    for (RRset set : cem.getSectionRRsets(Section.AUTHORITY)) {
      // hash(n=sub.nsec3.ingotronic.ch.,it=10,s=1234)=5RFQOLI81S6LKQTUG5HLI19UVJNKUL3H
      if (set.getName().toString().startsWith("5RFQOLI81S6LKQTUG5HLI19UVJNKUL3H")) {
        delegationNsec = set.first();
        delegationNsecSig = set.sigs().get(0);
        break;
      }
    }

    Message m = resolver.send(createMessage("a.sub.nsec3.ingotronic.ch./A"));
    String temp = m.toString().replaceAll("^sub\\.nsec3.*", "");
    // hash(n=sub.nsec3.ingotronic.ch.,it=11,s=4321)=8N8QLBCUIH7R2BG7DMCJ5AEE63K4KVUA
    temp = temp.replaceAll("8N8QLBCUIH7R2BG7DMCJ5AEE63K4KVUA.*", "");
    Message message = messageFromString(temp);
    message.addRecord(delegationNsec, Section.AUTHORITY);
    message.addRecord(delegationNsecSig, Section.AUTHORITY);
    add("a.sub.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("a.sub.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals("failed.nxdomain.nsec3_bogus", getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  @AlwaysOffline
  void testNsec3ClosestEncloserIsInsecureDelegation() throws IOException {
    Message response = resolver.send(createMessage("a.unsigned.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertEquals("failed.nxdomain.nsec3_insecure", getReason(response));
    assertEde(-1, response);
  }

  @Test
  void testNsecEcdsa256() throws IOException {
    Provider[] providers = Security.getProviders("KeyFactory.EC");
    Assumptions.assumeTrue(providers != null && providers.length > 0);

    Message response = resolver.send(createMessage("www.wc.nsec3-ecdsa256.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEde(-1, response);
  }

  @Test
  void testNsecEcdsa384() throws IOException {
    Provider[] providers = Security.getProviders("KeyFactory.EC");
    Assumptions.assumeTrue(providers != null && providers.length > 0);

    Message response = resolver.send(createMessage("www.wc.nsec3-ecdsa384.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEde(-1, response);
  }
}
