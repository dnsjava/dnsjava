// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Rcode;

class TestBogusReasonMessage extends TestBase {
  @Test
  void testLongBogusReasonIsSplitCorrectly() throws IOException {
    Message response =
        resolver.send(
            createMessage(
                "01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.isc.org./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertEquals(
        "failed.nxdomain.authority:{ isc.org. 2962 IN NSEC [01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.01234567890123456789012345678901234567890123456789.isc.org. A NS SOA MX TXT AAAA NAPTR RRSIG NSEC DNSKEY SPF] sigs: [NSEC 5 2 3600 20160706234032 20160606234032 13953 isc.org. fnOJeQG2vOwrERAPIqAenLOosbIBT7UvmxOV8Az2ExOhlGxP2CEqZEc5NPVbidq4oZC2kHyG7x31D6LBJXeXgOuanv+uqPNe9UIiUhdj+Egf8FEWIOKp8nxgjQGiGSNbQenWjeWoR91sReFEU+Pn7NPlEI072MzEESOT8oVucx8=] }",
        getReason(response));
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }
}
