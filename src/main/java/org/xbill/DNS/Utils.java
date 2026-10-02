// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@UtilityClass
class Utils {
  static final String SECURE_RANDOM_ALGORITHM_PROPERTY = "dnsjava.secure_random_algorithm";

  /**
   * Creates a {@link SecureRandom} using the algorithm named by the {@code
   * dnsjava.secure_random_algorithm} system property. Falls back to a default {@link SecureRandom}
   * when the property is not set or names an algorithm that is not available.
   */
  static SecureRandom secureRandom() {
    String algorithm = System.getProperty(SECURE_RANDOM_ALGORITHM_PROPERTY);
    if (algorithm != null && !algorithm.isEmpty()) {
      try {
        return SecureRandom.getInstance(algorithm);
      } catch (NoSuchAlgorithmException e) {
        log.warn(
            "SecureRandom algorithm '{}' requested via {} is not available, falling back to the default",
            algorithm,
            SECURE_RANDOM_ALGORITHM_PROPERTY);
      }
    }
    return new SecureRandom();
  }

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
