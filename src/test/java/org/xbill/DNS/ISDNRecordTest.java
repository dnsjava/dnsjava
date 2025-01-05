// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class ISDNRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_5arg() {
    ISDNRecord isdn = new ISDNRecord(n, DClass.IN, 0, "foo", "bar");
    assertEquals("foo", isdn.getAddress());
    assertEquals("bar", isdn.getSubAddress());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("150862028003217 004");
    ISDNRecord isdn = new ISDNRecord();
    isdn.rdataFromString(t, null);
    assertEquals("150862028003217", isdn.getAddress());
    assertEquals("004", isdn.getSubAddress());
  }
}
