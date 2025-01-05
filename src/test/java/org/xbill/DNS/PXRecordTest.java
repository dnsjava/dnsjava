// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class PXRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("10   net2.it.  PRMD-net2.ADMD-p400.C-it.");
    PXRecord pxRecord = new PXRecord();
    pxRecord.rdataFromString(t, null);
    assertEquals(10, pxRecord.getPreference());
    assertEquals(Name.fromConstantString("net2.it."), pxRecord.getMap822());
    assertEquals(Name.fromConstantString("PRMD-net2.ADMD-p400.C-it."), pxRecord.getMapX400());
  }
}
