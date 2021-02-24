// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base64;

class OPENPGPKEYRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("CAFEBABE");
    OPENPGPKEYRecord record = new OPENPGPKEYRecord();
    record.rdataFromString(t, null);
    assertArrayEquals(base64.fromString("CAFEBABE"), record.getCert());
  }
}
