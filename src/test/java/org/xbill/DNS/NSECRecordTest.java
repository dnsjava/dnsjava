// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class NSECRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("host.example.com. A MX RRSIG NSEC TYPE1234");
    NSECRecord nsecRecord = new NSECRecord();
    nsecRecord.rdataFromString(t, null);
    assertThat(nsecRecord.getNext()).isEqualTo(Name.fromConstantString("host.example.com."));
    assertThat(nsecRecord.hasType(-1)).isFalse();
  }
}
