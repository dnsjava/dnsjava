// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

public class TSIGRecordTest {
  @Test
  void testTsigToStringFudge() {
    TSIGRecord r =
        new TSIGRecord(
            Name.root,
            DClass.IN,
            60,
            TSIG.HMAC_MD5,
            Instant.ofEpochSecond(1),
            Duration.ofSeconds(5),
            new byte[16],
            1,
            0,
            null);
    assertEquals(
        "HMAC-MD5.SIG-ALG.REG.INT. 1 5 16 AAAAAAAAAAAAAAAAAAAAAA== NOERROR 0", r.rrToString());
  }
}
