// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.utils;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class BaseUtilsTest {
  @ParameterizedTest
  @ValueSource(ints = {8, 10, 24, 63, 64, 65})
  void testWrapLines(int lineLength) {
    String toWrap = String.format("%0" + ((lineLength * 3) + 5) + "d", 0);
    String out = BaseUtils.wrapLines(toWrap, lineLength, "", false);
    String[] lines = out.split("\n");
    assertThat(lines).hasSize(4);
    assertThat(lines[3]).hasSize(5);
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 10, 24, 63, 64, 65})
  void testWrapLinesEndsWith(int lineLength) {
    String toWrap = String.format("%0" + ((lineLength * 3) + 5) + "d", 0);
    String out = BaseUtils.wrapLines(toWrap, lineLength, "", true);
    assertThat(out.charAt(out.length() - 1)).isEqualTo(')');
  }

  @ParameterizedTest
  @ValueSource(ints = {8, 10, 24, 63, 64, 65})
  void testWrapLinesPrefix(int lineLength) {
    String toWrap = String.format("%0" + ((lineLength * 3) + 5) + "d", 0);
    String out = BaseUtils.wrapLines(toWrap, lineLength, "\t", false);
    String[] lines = out.split("\n");
    for (String line : lines) {
      assertThat(line).startsWith("\t");
    }
  }
}
