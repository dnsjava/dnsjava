// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class DHCIDRecordTest {
  @Test
  void emptyCertInCtorThrows() {
    assertThatThrownBy(() -> new DHCIDRecord(Name.root, DClass.IN, 0, new byte[0]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("data is required and must be non-empty");
    assertThatThrownBy(() -> new DHCIDRecord(Name.root, DClass.IN, 0, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("data is required and must be non-empty");
  }

  @ParameterizedTest
  @ValueSource(strings = {"", " ", "\"\""})
  void emptyCertInPresentationThrows(String input) {
    try (Tokenizer t = new Tokenizer(input)) {
      DHCIDRecord r = new DHCIDRecord();
      assertThatThrownBy(() -> r.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class)
          .hasMessageEndingWith("data is required and must be non-empty");
    }
  }

  @Test
  void emptyCertFromWireThrows() {
    DHCIDRecord r = new DHCIDRecord();
    assertThatThrownBy(() -> r.rrFromWire(new DNSInput(new byte[0])))
        .isInstanceOf(WireParseException.class)
        .hasMessage("data is required and must be non-empty");
  }
}
