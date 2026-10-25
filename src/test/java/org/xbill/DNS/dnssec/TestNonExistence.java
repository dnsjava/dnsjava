// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

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
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testDoubleLabelABelowSignedNsec3MissingNsec3() throws IOException {
    Message m = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
    Message message =
        messageFromString(m.toString().replaceAll("L40.+nsec3\\.ingotronic\\.ch\\.\\s+300.*", ""));
    add("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("gibtsnicht.gibtsnicht.nsec3.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response)).isEqualTo("failed.nxdomain.nsec3_bogus");
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testDoubleLabelABelowSignedBeforeZoneNsec3() throws IOException {
    // the query name here must hash to a name BEFORE the first existing
    // NSEC3 owner name
    Message response = resolver.send(createMessage("alias.1gibtsnicht.nsec3.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
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
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertThat(response.getSectionRRsets(Section.ANSWER)).isEmpty();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testNxDomainWithInvalidNsecSignature() throws IOException {
    Message m = resolver.send(createMessage("x.ingotronic.ch./A"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("x.ingotronic.ch./A", message);

    Message response = resolver.send(createMessage("x.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response)).startsWith("failed.nxdomain.authority");
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNoDataWithInvalidNsecSignature() throws IOException {
    Message m = resolver.send(createMessage("www.ingotronic.ch./MX"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\sNSEC\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("www.ingotronic.ch./MX", message);

    Message response = resolver.send(createMessage("www.ingotronic.ch./MX"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response)).startsWith("failed.authority.nodata");
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testNoDataOnENT() throws IOException {
    Message response = resolver.send(createMessage("b.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEde(-1, response);
  }
}
