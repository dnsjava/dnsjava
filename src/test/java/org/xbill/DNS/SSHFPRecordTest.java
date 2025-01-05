// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

class SSHFPRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("2 1 CAFEBABE");
    SSHFPRecord sshfpRecord = new SSHFPRecord();
    sshfpRecord.rdataFromString(t, null);
    assertEquals(SSHFPRecord.Algorithm.DSS, sshfpRecord.getAlgorithm());
    assertEquals(SSHFPRecord.Digest.SHA1, sshfpRecord.getDigestType());
    assertArrayEquals(base16.fromString("CAFEBABE"), sshfpRecord.getFingerPrint());
  }
}
