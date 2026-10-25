// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NSAPRecordTest {
  @SuppressWarnings("deprecation")
  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00");
    NSAPRecord nsap = new NSAPRecord();
    nsap.rdataFromString(t, null);
    assertThat(nsap.getAddress())
        .isEqualTo(
            "G\\000\\005\\128\\000Z\\000\\000\\000\\000\\001\\2253\\255\\255\\255\\000\\001a\\000");
    assertThat(nsap.getAddressAsByteArray())
        .containsExactly(
            new byte[] {
              71,
              0,
              5,
              (byte) 128,
              0,
              90,
              0,
              0,
              0,
              0,
              1,
              (byte) 225,
              51,
              (byte) 255,
              (byte) 255,
              (byte) 255,
              0,
              1,
              97,
              0
            });
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "", " ", "\"\"", "0", " 0",
      })
  void rdataFromStringShortAddress(String value) {
    try (Tokenizer t = new Tokenizer(value)) {
      NSAPRecord nsap = new NSAPRecord();
      assertThatThrownBy(() -> nsap.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class);
    }
  }
}
