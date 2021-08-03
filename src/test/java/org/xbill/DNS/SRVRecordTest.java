// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class SRVRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("0 5 5060 sipserver.example.com.");
    SRVRecord record = new SRVRecord();
    record.rdataFromString(t, null);
    assertEquals(0, record.getPriority());
    assertEquals(5, record.getWeight());
    assertEquals(5060, record.getPort());
    assertEquals(Name.fromConstantString("sipserver.example.com."), record.getTarget());
    assertEquals(record.getAdditionalName(), record.getTarget());
  }
}
