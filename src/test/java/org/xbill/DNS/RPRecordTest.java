// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class RPRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("louie.trantor.umd.edu.  LAM1.people.umd.edu.");
    RPRecord rpRecord = new RPRecord();
    rpRecord.rdataFromString(t, null);
    assertEquals(Name.fromConstantString("louie.trantor.umd.edu."), rpRecord.getMailbox());
    assertEquals(Name.fromConstantString("LAM1.people.umd.edu."), rpRecord.getTextDomain());
  }
}
