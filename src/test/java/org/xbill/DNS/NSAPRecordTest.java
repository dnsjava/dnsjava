// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class NSAPRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00");
    NSAPRecord nsap = new NSAPRecord();
    nsap.rdataFromString(t, null);
    assertEquals(
        "G\\000\\005\\128\\000Z\\000\\000\\000\\000\\001\\2253\\255\\255\\255\\000\\001a\\000",
        nsap.getAddress());
  }
}
