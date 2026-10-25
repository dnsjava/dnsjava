// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class NSEC3PARAMRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("1 1 10 5053851B");
    NSEC3PARAMRecord nsec3PARAMRecord = new NSEC3PARAMRecord();
    nsec3PARAMRecord.rdataFromString(t, null);
    assertThat(nsec3PARAMRecord.getHashAlgorithm()).isEqualTo(NSEC3Record.Digest.SHA1);
    assertThat(nsec3PARAMRecord.getFlags()).isEqualTo(NSEC3Record.Flags.OPT_OUT);
    assertThat(nsec3PARAMRecord.getSalt()).isNotNull();
  }
}
