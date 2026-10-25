// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

class TestKeyCacheUsage extends TestBase {

  @Test
  void testUnsigned() throws IOException {
    Message response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(firstA(response)).isEqualTo(localhost);
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec");
    assertEde(-1, response);

    // send the query a second time to ensure the cache doesn't create a wrong behavior
    response = resolver.send(createMessage("www.unsigned.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(firstA(response)).isEqualTo(localhost);
    assertThat(getReason(response)).isEqualTo("insecure.ds.nsec");
    assertEde(-1, response);
  }
}
