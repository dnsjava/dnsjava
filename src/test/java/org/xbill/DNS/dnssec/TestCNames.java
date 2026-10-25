// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

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
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(response.getSection(Section.ANSWER).size()).isEqualTo(3);
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec3");
    assertEde(-1, response);
  }

  @Test
  void testCNameToUnsignedMX() throws IOException {
    Message response = resolver.send(createMessage("cunsinged.ingotronic.ch./MX"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(response.getSection(Section.ANSWER).size()).isEqualTo(2);
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec3");
    assertEde(-1, response);
  }

  @Test
  void testCNameToSignedA() throws IOException {
    Message response = resolver.send(createMessage("csigned.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(response.getSection(Section.ANSWER).size()).isEqualTo(4);
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testCNameToSignedMX() throws IOException {
    Message response = resolver.send(createMessage("csigned.ingotronic.ch./MX"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(response.getSection(Section.ANSWER).size()).isEqualTo(2);
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testCNameToSignedAExternal() throws IOException {
    Message response = resolver.send(createMessage("csext.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(response.getSection(Section.ANSWER).size()).isEqualTo(4);
    assertThat(response.getSection(Section.AUTHORITY).size()).isEqualTo(5);
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testCNameToInvalidSigned() throws IOException {
    Message response = resolver.send(createMessage("cfailed.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response))
        .isEqualTo(
            "validate.bogus.badkey:dnssec-failed.org.:dnskey.no_ds_alg_match:dnssec-failed.org.:RSASHA1");
    assertEde(ExtendedErrorCodeOption.DNSKEY_MISSING, response);
  }

  @Test
  void testCNameToUnsignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("cunsinged.nsec3.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec3");
    assertEde(-1, response);
  }

  @Test
  void testCNameToSignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("csigned.nsec3.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testCNameToInvalidSignedNsec3() throws IOException {
    Message response = resolver.send(createMessage("cfailed.nsec3.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response))
        .isEqualTo(
            "validate.bogus.badkey:dnssec-failed.org.:dnskey.no_ds_alg_match:dnssec-failed.org.:RSASHA1");
    assertEde(ExtendedErrorCodeOption.DNSKEY_MISSING, response);
  }

  @ParameterizedTest(name = "testCNameToVoid_{index}")
  @CsvSource({"cvoid1,2", "cvoid2,4", "cvoid3,6"})
  void testCNameToVoid(String subdomain, int acount) throws IOException {
    Message response = resolver.send(createMessage(subdomain + ".ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(response.getSection(Section.ANSWER).size()).isEqualTo(acount);
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testCNameToUnsignedVoid() throws IOException {
    Message response = resolver.send(createMessage("cvoid4.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec");
    assertEde(-1, response);
  }

  @Test
  void testCNameToExternalUnsignedVoid() throws IOException {
    Message response = resolver.send(createMessage("cvoid.dnssectest.jitsi.net./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec3");
    assertEde(-1, response);
  }

  @Test
  void testCNameToSubSigned() throws IOException {
    Message response = resolver.send(createMessage("cssub.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testCNameToVoidExternalInvalidTld() throws IOException {
    Message response = resolver.send(createMessage("cvoidext1.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(response.getSection(Section.ANSWER).size()).isEqualTo(2);
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testCNameToVoidExternalValidTld() throws IOException {
    Message response = resolver.send(createMessage("cvoidext2.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testCNameToVoidNsec3() throws IOException {
    Message response = resolver.send(createMessage("cvoid.nsec3.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }
}
