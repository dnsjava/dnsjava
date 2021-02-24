// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base64;

class CERTRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("PGP 0 0 CAFEBABE");
    CERTRecord record = new CERTRecord();
    record.rdataFromString(t, null);
    assertEquals(0, record.getAlgorithm());
    assertEquals(0, record.getKeyTag());
    assertArrayEquals(base64.fromString("CAFEBABE"), record.getCert());
  }
}
