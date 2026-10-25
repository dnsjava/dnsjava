// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class NXTRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("medium.foo.tld. A MX SIG NXT");
    NXTRecord nxtRecord = new NXTRecord();
    nxtRecord.rdataFromString(t, null);
    assertThat(nxtRecord.getNext()).isEqualTo(Name.fromConstantString("medium.foo.tld."));
    assertThat(nxtRecord.getBitmap()).isNotNull();
  }
}
