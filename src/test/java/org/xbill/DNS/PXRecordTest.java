// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class PXRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("10   net2.it.  PRMD-net2.ADMD-p400.C-it.");
    PXRecord pxRecord = new PXRecord();
    pxRecord.rdataFromString(t, null);
    assertThat(pxRecord.getPreference()).isEqualTo(10);
    assertThat(pxRecord.getMap822()).isEqualTo(Name.fromConstantString("net2.it."));
    assertThat(pxRecord.getMapX400())
        .isEqualTo(Name.fromConstantString("PRMD-net2.ADMD-p400.C-it."));
  }
}
