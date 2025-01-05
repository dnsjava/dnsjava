// SPDX-License-Identifier: BSD-3-Clause
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
    CERTRecord cert = new CERTRecord();
    cert.rdataFromString(t, null);
    assertEquals(0, cert.getAlgorithm());
    assertEquals(0, cert.getKeyTag());
    assertArrayEquals(base64.fromString("CAFEBABE"), cert.getCert());
  }
}
