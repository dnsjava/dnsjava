// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class ExtendedErrorCodeOptionTest {
  @Test
  void testCodeOnly() throws IOException {
    byte[] data =
        new byte[] {
          0,
          15, // EDNS option code
          0,
          2, // option data length
          0,
          1 // extended error code
        };
    EDNSOption option = EDNSOption.fromWire(data);
    assertTrue(option instanceof ExtendedErrorCodeOption, "Expected ExtendedErrorCodeOption");
    ExtendedErrorCodeOption ede = (ExtendedErrorCodeOption) option;
    assertEquals(1, ede.getErrorCode());
    assertNull(ede.getText());
    assertArrayEquals(data, ede.toWire());
    assertArrayEquals(data, new ExtendedErrorCodeOption(1).toWire());
  }

  @Test
  void testCodeAndText() throws IOException {
    byte[] data =
        new byte[] {
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
    assertTrue(option instanceof ExtendedErrorCodeOption, "Expected ExtendedErrorCodeOption");
    ExtendedErrorCodeOption ede = (ExtendedErrorCodeOption) option;
    assertEquals(1, ede.getErrorCode());
    assertEquals("ab", ede.getText());
    assertArrayEquals(data, ede.toWire());
    assertArrayEquals(data, new ExtendedErrorCodeOption(1, "ab").toWire());
  }

  @Test
  void testCodeAndTextNullTerminated() throws IOException {
    byte[] inputData =
        new byte[] {
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
    assertTrue(option instanceof ExtendedErrorCodeOption, "Expected ExtendedErrorCodeOption");
    ExtendedErrorCodeOption ede = (ExtendedErrorCodeOption) option;
    assertEquals(1, ede.getErrorCode());
    assertEquals("ab", ede.getText());

    byte[] outputDataNonNullTerminated =
        new byte[] {
          0,
          15, // EDNS option code
          0,
          4, // option data length
          0,
          1, // extended error code
          (byte) 'a',
          (byte) 'b',
        };
    assertArrayEquals(outputDataNonNullTerminated, ede.toWire());
  }

  @Test
  void testToStringCodeOnly() {
    ExtendedErrorCodeOption option = new ExtendedErrorCodeOption(1);
    assertEquals("Unsupported DNSKEY Algorithm", option.optionToString());
  }

  @Test
  void testToStringUnknownCode() {
    ExtendedErrorCodeOption option = new ExtendedErrorCodeOption(49152);
    assertEquals("EDE49152", option.optionToString());
  }

  @Test
  void testToStringCodeAndText() {
    ExtendedErrorCodeOption option = new ExtendedErrorCodeOption(1, "ab");
    assertEquals("Unsupported DNSKEY Algorithm: ab", option.optionToString());
  }
}
