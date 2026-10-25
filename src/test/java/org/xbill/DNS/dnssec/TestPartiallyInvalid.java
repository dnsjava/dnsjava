// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

class TestPartiallyInvalid extends TestBase {
  @Test
  void testValidExising() throws IOException {
    Message response = resolver.send(createMessage("www.partial.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(firstA(response)).isEqualTo(localhost);
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testValidExisingNoType() throws IOException {
    Message response = resolver.send(createMessage("www.partial.ingotronic.ch./MX"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(isEmptyAnswer(response)).isTrue();
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testValidNonExising() throws IOException {
    Message response = resolver.send(createMessage("www.gibtsnicht.partial.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NXDOMAIN, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }
}
