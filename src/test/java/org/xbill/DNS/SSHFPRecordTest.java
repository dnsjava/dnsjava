// SPDX-License-Identifier: BSD-2-Clause
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
    SSHFPRecord record = new SSHFPRecord();
    record.rdataFromString(t, null);
    assertEquals(SSHFPRecord.Algorithm.DSS, record.getAlgorithm());
    assertEquals(SSHFPRecord.Digest.SHA1, record.getDigestType());
    assertArrayEquals(base16.fromString("CAFEBABE"), record.getFingerPrint());
  }
}
