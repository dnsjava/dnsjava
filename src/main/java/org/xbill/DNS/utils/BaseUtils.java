// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.utils;

import lombok.experimental.UtilityClass;

@UtilityClass
class BaseUtils {
  /**
   * Wrap a long string at {@code lineLength} characters.
   *
   * @param s The string to wrap.
   * @param lineLength The number of characters per line.
   * @param prefix A string prefixing the characters on each line.
   * @param addClose Whether to add a close parenthesis or not.
   * @return The wrapped string.
   */
  String wrapLines(String s, int lineLength, String prefix, boolean addClose) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < s.length(); i += lineLength) {
      sb.append(prefix);
      if (i + lineLength >= s.length()) {
        sb.append(s.substring(i));
        if (addClose) {
          sb.append(" )");
        }
      } else {
        sb.append(s, i, i + lineLength);
        sb.append("\n");
      }
    }
    return sb.toString();
  }
}
