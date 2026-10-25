// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Section;

class TestPositive extends TestBase {
  @Test
  void testValidExising() throws IOException {
    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(firstA(response)).isEqualTo(localhost);
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testValidNonExising() throws IOException {
    Message response = resolver.send(createMessage("ingotronic.ch./ANY"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testValidAnswerToDifferentQueryTypeIsBogus() throws IOException {
    // Fetch a regular 'A' response, then replace the query with MX
    Message m = resolver.send(createMessage("www.ingotronic.ch./A"));
    m.removeAllRecords(Section.QUESTION);
    m.addRecord(
        new MXRecord(
            Name.fromConstantString("www.ingotronic.ch."),
            DClass.IN,
            3600,
            0,
            Name.fromConstantString("www.ingotronic.ch.")),
        Section.QUESTION);

    // Assert that this results in bogus nodata/nsec missing after message normalization
    add("www.ingotronic.ch./A", m);
    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response)).isEqualTo("failed.nodata");
    assertEde(ExtendedErrorCodeOption.NSEC_MISSING, response);
  }

  @Test
  void testCDonQueryDoesntDoAnything() throws IOException {
    Message m = resolver.send(createMessage("www.ingotronic.ch./A"));
    Message message =
        messageFromString(
            m.toString().replaceAll("(.*\\sRRSIG\\s+A\\s(\\d+\\s+){6}.*\\.)(.*)", "$1 YXNkZg=="));
    add("www.ingotronic.ch./A", message);

    Message query = createMessage("www.ingotronic.ch./A");
    query.getHeader().setFlag(Flags.CD);
    Message response = resolver.send(query);
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }
}
