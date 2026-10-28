// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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

  @Test
  void quotingSemicolon() {
    // RFC 1035 Section 5.1: The comment starts with a ';' (semicolon).
    // ';' (semicolon) inside a string
    Record r = new TXTRecord(Name.root, DClass.IN, 0, "v=DMARC1;p=reject");
    assertThat(r.rdataToString()).isEqualTo("\"v=DMARC1;p=reject\"");
  }

  @ParameterizedTest
  @ValueSource(strings = {"aa(bb", "aa)bb", "aa(bb)cc"})
  void quotingParentheses(String value) {
    // RFC 1035 Section 5.1: Parentheses are used to group data that crosses a line boundary.
    // '(' and/or ')' inside a string
    Record r = new TXTRecord(Name.root, DClass.IN, 0, value);
    assertThat(r.rdataToString()).isEqualTo("\"" + value + "\"");
  }
}
