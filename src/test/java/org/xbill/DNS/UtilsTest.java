// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.SecureRandom;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class UtilsTest {
  @AfterEach
  void clearProperty() {
    System.clearProperty(Utils.SECURE_RANDOM_ALGORITHM_PROPERTY);
  }

  @Test
  void secureRandom_defaultWhenPropertyUnset() {
    System.clearProperty(Utils.SECURE_RANDOM_ALGORITHM_PROPERTY);
    SecureRandom random = Utils.secureRandom();
    assertNotNull(random);
    assertNotNull(generate(random));
  }

  @Test
  void secureRandom_usesConfiguredAlgorithm() {
    System.setProperty(Utils.SECURE_RANDOM_ALGORITHM_PROPERTY, "SHA1PRNG");
    SecureRandom random = Utils.secureRandom();
    assertNotNull(random);
    assertNotNull(generate(random));
  }

  @Test
  void secureRandom_fallsBackForInvalidAlgorithm() {
    System.setProperty(Utils.SECURE_RANDOM_ALGORITHM_PROPERTY, "NoSuchAlgorithmPRNG");
    SecureRandom random = Utils.secureRandom();
    assertNotNull(random);
    assertNotNull(generate(random));
  }

  private static byte[] generate(SecureRandom random) {
    byte[] bytes = new byte[8];
    random.nextBytes(bytes);
    return bytes;
  }
}
