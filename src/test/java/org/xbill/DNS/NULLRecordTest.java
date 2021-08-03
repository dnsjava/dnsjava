// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class NULLRecordTest {

  @Test
  void rdataFromString() {
    TextParseException thrown =
        assertThrows(
            TextParseException.class,
            () -> new NULLRecord().rdataFromString(new Tokenizer(" "), null));
    assertTrue(thrown.getMessage().contains("no defined text format for NULL records"));
  }
}
