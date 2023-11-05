// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class BaseUtilsTest {
  @ParameterizedTest
  @ValueSource(ints = {8, 10, 24, 63, 64, 65})
  void testWrapLines(int lineLength) {
    String toWrap = String.format("%0" + ((lineLength * 3) + 5) + "d", 0);
    String out = BaseUtils.wrapLines(toWrap, lineLength, "", false);
    String[] lines = out.split("\n");
    assertEquals(4, lines.length);
    assertEquals(5, lines[3].length());
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 10, 24, 63, 64, 65})
  void testWrapLinesEndsWith(int lineLength) {
    String toWrap = String.format("%0" + ((lineLength * 3) + 5) + "d", 0);
    String out = BaseUtils.wrapLines(toWrap, lineLength, "", true);
    assertEquals(')', out.charAt(out.length() - 1));
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 10, 24, 63, 64, 65})
  void testWrapLinesPrefix(int lineLength) {
    String toWrap = String.format("%0" + ((lineLength * 3) + 5) + "d", 0);
    String out = BaseUtils.wrapLines(toWrap, lineLength, "\t", false);
    String[] lines = out.split("\n");
    for (String line : lines) {
      assertTrue(line.startsWith("\t"), "Line start with prefix");
    }
  }
}
