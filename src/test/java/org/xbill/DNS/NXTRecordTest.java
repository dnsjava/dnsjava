// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class NXTRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("medium.foo.tld. A MX SIG NXT");
    NXTRecord record = new NXTRecord();
    record.rdataFromString(t, null);
    assertEquals(Name.fromConstantString("medium.foo.tld."), record.getNext());
    assertNotNull(record.getBitmap());
  }
}
