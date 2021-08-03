// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TKEYRecordTest {

  @Test
  void rdataFromString() {
    TextParseException thrown =
        assertThrows(
            TextParseException.class,
            () -> new TKEYRecord().rdataFromString(new Tokenizer(" "), null));
    assertTrue(thrown.getMessage().contains("no text format defined for TKEY"));
  }
}
