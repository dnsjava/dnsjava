// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import lombok.experimental.UtilityClass;

@UtilityClass
class Utils {
  static boolean isUInt8(int value) {
    return value >= 0 && value <= 255;
  }

  static boolean isUInt8(long value) {
    return value >= 0 && value <= 255;
  }

  static boolean isUInt16(int value) {
    return value >= 0 && value <= 0xffff;
  }

  static boolean isUInt16(long value) {
    return value >= 0 && value <= 0xffff;
  }

  static boolean isUInt32(long value) {
    return value >= 0 && value <= 0xffffffffL;
  }
}
