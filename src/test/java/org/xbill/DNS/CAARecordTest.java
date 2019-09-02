package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class CAARecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_6arg() {
    CAARecord record = new CAARecord(n, DClass.IN, 0, CAARecord.Flags.IssuerCritical, "", "");
    assertEquals(CAARecord.Flags.IssuerCritical, record.getFlags());
    assertEquals("", record.getTag());
    assertEquals("", record.getValue());

    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new CAARecord(
                    n,
                    DClass.IN,
                    0xABCDEL,
                    CAARecord.Flags.IssuerCritical,
                    new String(new char[256]),
                    ""));
    assertEquals("text string too long", thrown.getMessage());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer(CAARecord.Flags.IssuerCritical + " issue entrust.net");
    CAARecord record = new CAARecord();
    record.rdataFromString(t, null);
    assertEquals("issue", record.getTag());
    assertEquals("entrust.net", record.getValue());
  }
}
