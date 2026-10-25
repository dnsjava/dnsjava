// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class SPFRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("v=spf1 a mx ip4:69.64.153.131 include:_spf.google.com ~all");
    SPFRecord spfRecord = new SPFRecord();
    spfRecord.rdataFromString(t, null);
    assertThat(spfRecord.getStrings()).hasSize(6);
    assertThat(spfRecord.getStringsAsByteArrays()).hasSize(6);
  }
}
