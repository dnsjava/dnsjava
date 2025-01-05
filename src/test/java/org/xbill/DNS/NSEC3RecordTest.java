// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class NSEC3RecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t =
        new Tokenizer(
            "1 1 10 5053851B PF2TNEL79K4HTCBINCDBE9FPBU5I04KD A NS SOA MX AAAA RRSIG DNSKEY NSEC3PARAM TYPE65534");
    NSEC3Record nsec3Record = new NSEC3Record();
    nsec3Record.rdataFromString(t, null);
    assertEquals(NSEC3Record.Digest.SHA1, nsec3Record.getHashAlgorithm());
    assertEquals(NSEC3Record.Flags.OPT_OUT, nsec3Record.getFlags());
    assertNotNull(nsec3Record.getSalt());
    nsec3Record = new NSEC3Record();
    nsec3Record.rdataFromString(
        new Tokenizer(
            "1 1 10 - PF2TNEL79K4HTCBINCDBE9FPBU5I04KD A NS SOA MX AAAA RRSIG DNSKEY NSEC3PARAM TYPE65534"),
        null);
    assertNull(nsec3Record.getSalt());
  }
}
