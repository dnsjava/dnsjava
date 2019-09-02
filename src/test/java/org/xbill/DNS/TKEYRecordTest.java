package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class TKEYRecordTest {

  @Test
  void rdataFromString() throws IOException {
    TextParseException thrown =
        assertThrows(
            TextParseException.class,
            () -> new TKEYRecord().rdataFromString(new Tokenizer(" "), null));
    assertTrue(thrown.getMessage().contains("no text format defined for TKEY"));
  }
}
