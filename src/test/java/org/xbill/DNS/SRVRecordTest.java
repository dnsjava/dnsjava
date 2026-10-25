// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class SRVRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("0 5 5060 sipserver.example.com.");
    SRVRecord srvRecord = new SRVRecord();
    srvRecord.rdataFromString(t, null);
    assertThat(srvRecord.getPriority()).isZero();
    assertThat(srvRecord.getWeight()).isEqualTo(5);
    assertThat(srvRecord.getPort()).isEqualTo(5060);
    assertThat(srvRecord.getTarget()).isEqualTo(Name.fromConstantString("sipserver.example.com."));
    assertThat(srvRecord.getTarget()).isEqualTo(srvRecord.getAdditionalName());
  }
}
