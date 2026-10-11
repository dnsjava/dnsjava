// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

public class TXTRecordTest {
  @Test
  void encodingFromString() throws IOException {
    Record r = Record.fromString(Name.root, Type.TXT, DClass.IN, 0, "caf\\233", Name.root);
    assertThat(r.rdataToString()).isEqualTo("caf\\233");
  }

  @Test
  void encodingCtor() {
    // u009e -> Latin Small Letter E with Acute
    Record r = new TXTRecord(Name.root, Type.TXT, DClass.IN, "caf\u00e9");
    // As UTF-8: 0xC3 0xA9 (two bytes, because e acute is beyond 0x7f)
    assertThat(r.rdataToString()).isEqualTo("caf\\195\\169");
  }
}
