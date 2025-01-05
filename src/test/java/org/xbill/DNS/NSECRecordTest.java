// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class NSECRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("host.example.com. A MX RRSIG NSEC TYPE1234");
    NSECRecord nsecRecord = new NSECRecord();
    nsecRecord.rdataFromString(t, null);
    assertEquals(Name.fromConstantString("host.example.com."), nsecRecord.getNext());
    assertFalse(nsecRecord.hasType(-1));
  }
}
