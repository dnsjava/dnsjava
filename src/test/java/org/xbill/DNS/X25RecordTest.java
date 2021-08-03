// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class X25RecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("311061700956");
    X25Record record = new X25Record();
    record.rdataFromString(t, null);
    assertEquals("311061700956", record.getAddress());
  }
}
