// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class DLVRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_0arg() {
    DLVRecord dlv = new DLVRecord();
    assertEquals(0, dlv.getFootprint());
    assertEquals(0, dlv.getAlgorithm());
    assertEquals(0, dlv.getDigestID());
    assertNull(dlv.getDigest());
  }

  @Test
  void ctor_7arg() {
    DLVRecord dlv = new DLVRecord(n, DClass.IN, 0, 1, 2, 3, "".getBytes());
    assertEquals(1, dlv.getFootprint());
    assertEquals(2, dlv.getAlgorithm());
    assertEquals(3, dlv.getDigestID());
    assertEquals(0, dlv.getDigest().length);
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("60485 5 1 CAFEBABE");
    DLVRecord dlv = new DLVRecord();
    dlv.rdataFromString(t, null);
    assertEquals(60485, dlv.getFootprint());
    assertEquals(5, dlv.getAlgorithm());
    assertEquals(1, dlv.getDigestID());
    assertEquals(4, dlv.getDigest().length);
  }
}
