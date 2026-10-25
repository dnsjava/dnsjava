// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class ExtendedErrorCodeOptionTest {
  @Test
  void testCodeOnly() throws IOException {
    byte[] data = {
      0,
      15, // EDNS option code
      0,
      2, // option data length
      0,
      1 // extended error code
    };
    EDNSOption option = EDNSOption.fromWire(data);
    assertThat(option)
        .as("Expected ExtendedErrorCodeOption")
        .isInstanceOf(ExtendedErrorCodeOption.class);
    ExtendedErrorCodeOption ede = (ExtendedErrorCodeOption) option;
    assertThat(ede.getErrorCode()).isOne();
    assertThat(ede.getText()).isNull();
    assertThat(ede.toWire()).containsExactly(data);
    assertThat(new ExtendedErrorCodeOption(1).toWire()).containsExactly(data);
  }

  @Test
  void testCodeAndText() throws IOException {
    byte[] data = {
      0,
      15, // EDNS option code
      0,
      4, // option data length
      0,
      1, // extended error code
      (byte) 'a',
      (byte) 'b'
    };
    EDNSOption option = EDNSOption.fromWire(data);
    assertThat(option)
        .as("Expected ExtendedErrorCodeOption")
        .isInstanceOf(ExtendedErrorCodeOption.class);
    ExtendedErrorCodeOption ede = (ExtendedErrorCodeOption) option;
    assertThat(ede.getErrorCode()).isOne();
    assertThat(ede.getText()).isEqualTo("ab");
    assertThat(ede.toWire()).containsExactly(data);
    assertThat(new ExtendedErrorCodeOption(1, "ab").toWire()).containsExactly(data);
  }

  @Test
  void testCodeAndTextNullTerminated() throws IOException {
    byte[] inputData = {
      0,
      15, // EDNS option code
      0,
      5, // option data length
      0,
      1, // extended error code
      (byte) 'a',
      (byte) 'b',
      0
    };
    EDNSOption option = EDNSOption.fromWire(inputData);
    assertThat(option)
        .as("Expected ExtendedErrorCodeOption")
        .isInstanceOf(ExtendedErrorCodeOption.class);
    ExtendedErrorCodeOption ede = (ExtendedErrorCodeOption) option;
    assertThat(ede.getErrorCode()).isOne();
    assertThat(ede.getText()).isEqualTo("ab");

    byte[] outputDataNonNullTerminated = {
      0,
      15, // EDNS option code
      0,
      4, // option data length
      0,
      1, // extended error code
      (byte) 'a',
      (byte) 'b',
    };
    assertThat(ede.toWire()).containsExactly(outputDataNonNullTerminated);
  }

  @Test
  void testToStringCodeOnly() {
    ExtendedErrorCodeOption option = new ExtendedErrorCodeOption(1);
    assertThat(option.optionToString()).isEqualTo("UNSUPPORTED_DNSKEY_ALGORITHM");
  }

  @Test
  void testToStringUnknownCode() {
    ExtendedErrorCodeOption option = new ExtendedErrorCodeOption(49152);
    assertThat(option.optionToString()).isEqualTo("EDE49152");
  }

  @Test
  void testToStringCodeAndText() {
    ExtendedErrorCodeOption option = new ExtendedErrorCodeOption(1, "ab");
    assertThat(option.optionToString()).isEqualTo("UNSUPPORTED_DNSKEY_ALGORITHM: ab");
  }
}
