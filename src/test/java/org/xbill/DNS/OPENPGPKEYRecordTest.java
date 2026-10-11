// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base64;

class OPENPGPKEYRecordTest {
  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("CAFEBABE");
    OPENPGPKEYRecord openpgpkeyRecord = new OPENPGPKEYRecord();
    openpgpkeyRecord.rdataFromString(t, null);
    assertArrayEquals(base64.fromString("CAFEBABE"), openpgpkeyRecord.getCert());
  }

  @Test
  void emptyCertInCtorThrows() {
    assertThatThrownBy(() -> new OPENPGPKEYRecord(Name.root, DClass.IN, 0, new byte[0]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("cert is required and must be non-empty");
    assertThatThrownBy(() -> new OPENPGPKEYRecord(Name.root, DClass.IN, 0, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("cert is required and must be non-empty");
  }

  @Test
  void emptyCertInPresentationThrows() {
    try (Tokenizer t = new Tokenizer("")) {
      OPENPGPKEYRecord r = new OPENPGPKEYRecord();
      assertThatThrownBy(() -> r.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class)
          .hasMessageEndingWith("cert is required and must be non-empty");
    }
  }

  @Test
  void emptyCertFromWireThrows() {
    OPENPGPKEYRecord r = new OPENPGPKEYRecord();
    assertThatThrownBy(() -> r.rrFromWire(new DNSInput(new byte[0])))
        .isInstanceOf(WireParseException.class)
        .hasMessage("cert is required and must be non-empty");
  }
}
