// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.Test;

class NULLRecordTest {

  @Test
  void rdataFromString() {
    TextParseException thrown =
        assertThatExceptionOfType(TextParseException.class)
            .isThrownBy(() -> new NULLRecord().rdataFromString(new Tokenizer(" "), null))
            .actual();
    assertThat(thrown.getMessage()).contains("no defined text format for NULL records");
  }
}
