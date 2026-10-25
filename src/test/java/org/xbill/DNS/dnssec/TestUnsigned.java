// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

class TestUnsigned extends TestBase {
  @Test
  void testUnsignedBelowSignedZoneBind() throws IOException {
    Message response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(firstA(response)).isEqualTo(localhost);
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec");
    assertEde(-1, response);
  }

  @Test
  void testUnsignedBelowSignedTldNsec3NoOptOut() throws IOException {
    Message response = resolver.send(createMessage("20min.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec3");
    assertEde(-1, response);
  }

  @Test
  void testUnsignedBelowSignedTldNsec3OptOut() throws IOException {
    Message response = resolver.send(createMessage("yahoo.com./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec3");
    assertEde(-1, response);
  }

  @Test
  void testUnsignedBelowUnsignedZone() throws IOException {
    Message response = resolver.send(createMessage("www.sub.unsigned.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(firstA(response)).isEqualTo(localhost);
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec");
    assertEde(-1, response);
  }
}
