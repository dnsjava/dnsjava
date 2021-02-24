// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class ISDNRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_5arg() {
    ISDNRecord record = new ISDNRecord(n, DClass.IN, 0, "foo", "bar");
    assertEquals("foo", record.getAddress());
    assertEquals("bar", record.getSubAddress());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("150862028003217 004");
    ISDNRecord record = new ISDNRecord();
    record.rdataFromString(t, null);
    assertEquals("150862028003217", record.getAddress());
    assertEquals("004", record.getSubAddress());
  }
}
