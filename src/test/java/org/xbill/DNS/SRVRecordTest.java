// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class SRVRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("0 5 5060 sipserver.example.com.");
    SRVRecord srvRecord = new SRVRecord();
    srvRecord.rdataFromString(t, null);
    assertEquals(0, srvRecord.getPriority());
    assertEquals(5, srvRecord.getWeight());
    assertEquals(5060, srvRecord.getPort());
    assertEquals(Name.fromConstantString("sipserver.example.com."), srvRecord.getTarget());
    assertEquals(srvRecord.getAdditionalName(), srvRecord.getTarget());
  }
}
