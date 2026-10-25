// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

class TestDNames extends TestBase {
  @Test
  void testDNameToExistingIsValid() throws IOException {
    Message response = resolver.send(createMessage("www.alias.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(response.getSection(Section.ANSWER)).hasSize(5);
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testDNameToNoDataIsValid() throws IOException {
    Message response = resolver.send(createMessage("www.alias.ingotronic.ch./MX"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(response.getSection(Section.ANSWER)).hasSize(3);
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testDNameToNxDomainIsValid() throws IOException {
    Message response = resolver.send(createMessage("x.alias.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testDNameDirectQueryIsValid() throws IOException {
    Message response = resolver.send(createMessage("alias.ingotronic.ch./DNAME"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isNull();
    for (RRset set : response.getSectionRRsets(Section.ANSWER)) {
      if (set.getType() == Type.DNAME) {
        DNAMERecord r = (DNAMERecord) set.first();
        assertThat(r.getTarget()).isEqualTo(Name.fromString("ingotronic.ch."));
      }
    }
    assertEde(-1, response);
  }

  @Disabled("Now valid because of message normalization")
  @Test
  void testDNameWithFakedCnameIsInvalid() throws IOException {
    Message m = resolver.send(createMessage("www.alias.ingotronic.ch./A"));
    Message message =
        messageFromString(m.toString().replaceAll("(.*CNAME\\s+)(.*)", "$1 www.isc.org."));
    add("www.alias.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.alias.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response))
        .isEqualTo("failed.synthesize.nomatch:www.isc.org.:www.ingotronic.ch.");
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testDNameWithNoCnameIsValid() throws IOException {
    Message m = resolver.send(createMessage("www.isc.ingotronic.ch./A"));
    Message message =
        messageFromString(m.toString().replaceAll("(.*CNAME.*)", "").replaceAll("\n\n", "\n"));
    add("www.isc.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.isc.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertThat(response.getRcode()).isEqualTo(Rcode.NOERROR);
    assertThat(getReason(response)).isNull();
    Lookup l = new Lookup("www.isc.ingotronic.ch");
    l.setResolver(resolver);
    Record[] results = l.run();
    assertThat(results).isNotNull().hasSizeGreaterThanOrEqualTo(1);
    assertEde(-1, response);
  }

  @Disabled("Now valid because of message normalization")
  @Test
  void testDNameWithMultipleCnamesIsInvalid() throws IOException {
    Message m = resolver.send(createMessage("www.alias.ingotronic.ch./A"));
    Message message =
        messageFromString(m.toString().replaceAll("(.*CNAME.*)", "$1\n$1example.com."));
    add("www.alias.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.alias.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response)).isEqualTo("failed.synthesize.multiple");
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Disabled("Now valid because of message normalization")
  @Test
  void testDNameWithTooLongCnameIsInvalid() throws IOException {
    Message m = resolver.send(createMessage("www.n3.ingotronic.ch./A"));
    Message message =
        messageFromString(
            m.toString()
                .replaceAll(
                    "(.*\\.)(.*CNAME)",
                    "IamAVeryLongNameThatExeceedsTheMaximumOfTheAllowedDomainNameSys.temSpecificationLengthByAny.NumberThatAHumanOfTheSeventiesCouldHaveImagined.InThisSmallMindedWorldThatIs.NowAfterTheMillennium.InhabitedByOverSeven.BillionPeopleInFiveConts.n3.ingotronic.ch. $2"));
    add("www.n3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.n3.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response)).isEqualTo("failed.synthesize.toolong");
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testDNameInNsecIsUnderstood_Rfc6672_5_3_4_1() throws IOException {
    Message nsecs = resolver.send(createMessage("alias.ingotronic.ch./NS"));
    RRset nsecSet = null;
    for (RRset set : nsecs.getSectionRRsets(Section.AUTHORITY)) {
      if (set.getName().equals(Name.fromString("alias.ingotronic.ch."))) {
        nsecSet = set;
        break;
      }
    }

    Message message = new Message();
    message.getHeader().setRcode(Rcode.NXDOMAIN);
    message.addRecord(
        Record.newRecord(Name.fromString("www.alias.ingotronic.ch."), Type.A, DClass.IN),
        Section.QUESTION);
    for (Record r : nsecSet.rrs()) {
      message.addRecord(r, Section.AUTHORITY);
    }

    for (RRSIGRecord sig : nsecSet.sigs()) {
      message.addRecord(sig, Section.AUTHORITY);
    }

    add("www.alias.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("www.alias.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response)).isEqualTo("failed.nxdomain.exists:www.alias.ingotronic.ch.");
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testDNameToExternal() throws IOException {
    Message response = resolver.send(createMessage("www.isc.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testDNameChain() throws IOException {
    Message response = resolver.send(createMessage("www.alias.nsec3.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }
}
