// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class X25RecordTest {
  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("311061700956");
    X25Record x25Record = new X25Record();
    x25Record.rdataFromString(t, null);
    assertThat(x25Record.getAddress()).isEqualTo("311061700956");
  }

  @Test
  void rdataFromEmptyStringFails() {
    try (Tokenizer t = new Tokenizer("")) {
      X25Record x25Record = new X25Record();
      assertThatCode(() -> x25Record.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class);
    }
  }

  @Test
  void rdataFromStringRejectsUnicode() {
    // u0663 -> Arabic Eastern 3
    try (Tokenizer t = new Tokenizer("\u0663\u0663")) {
      X25Record x25Record = new X25Record();
      assertThatCode(() -> x25Record.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class);
    }
  }
}
