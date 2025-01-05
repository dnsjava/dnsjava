// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class CAARecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_6arg() {
    CAARecord caa = new CAARecord(n, DClass.IN, 0, CAARecord.Flags.IssuerCritical, "", "");
    assertEquals(CAARecord.Flags.IssuerCritical, caa.getFlags());
    assertEquals("", caa.getTag());
    assertEquals("", caa.getValue());

    String data = new String(new char[256]);
    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class,
            () -> new CAARecord(n, DClass.IN, 0xABCDEL, CAARecord.Flags.IssuerCritical, data, ""));
    assertEquals("text string too long", thrown.getMessage());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer(CAARecord.Flags.IssuerCritical + " issue entrust.net");
    CAARecord caa = new CAARecord();
    caa.rdataFromString(t, null);
    assertEquals("issue", caa.getTag());
    assertEquals("entrust.net", caa.getValue());
  }
}
