// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class NSEC3PARAMRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("1 1 10 5053851B");
    NSEC3PARAMRecord nsec3PARAMRecord = new NSEC3PARAMRecord();
    nsec3PARAMRecord.rdataFromString(t, null);
    assertEquals(NSEC3Record.Digest.SHA1, nsec3PARAMRecord.getHashAlgorithm());
    assertEquals(NSEC3Record.Flags.OPT_OUT, nsec3PARAMRecord.getFlags());
    assertNotNull(nsec3PARAMRecord.getSalt());
  }
}
