// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class PXRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("10   net2.it.  PRMD-net2.ADMD-p400.C-it.");
    PXRecord record = new PXRecord();
    record.rdataFromString(t, null);
    assertEquals(10, record.getPreference());
    assertEquals(Name.fromConstantString("net2.it."), record.getMap822());
    assertEquals(Name.fromConstantString("PRMD-net2.ADMD-p400.C-it."), record.getMapX400());
  }
}
