// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.Test;

class TKEYRecordTest {

  @Test
  void rdataFromString() {
    TextParseException thrown =
        assertThatExceptionOfType(TextParseException.class)
            .isThrownBy(() -> new TKEYRecord().rdataFromString(new Tokenizer(" "), null))
            .actual();
    assertThat(thrown.getMessage()).contains("no text format defined for TKEY");
  }
}
