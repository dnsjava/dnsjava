// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.Algorithm;

class DNSSECWithBCProviderTest {

  private static final String KEY_ALGORITHM = "RSA";
  private final byte[] toSign = "The quick brown fox jumped over the lazy dog.".getBytes();

  @BeforeAll
  static void beforeAll() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @AfterAll
  static void afterAll() {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
  }

  @Test
  void testSignWithDNSSECAndBCProvider() throws Exception {
    // generate a signature
    KeyPairGenerator keyPairGenerator =
        KeyPairGenerator.getInstance(KEY_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
    keyPairGenerator.initialize(512);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    int algorithm = Algorithm.RSASHA1;
    byte[] signature =
        DNSSEC.sign(
            keyPair.getPrivate(),
            keyPair.getPublic(),
            algorithm,
            toSign,
            BouncyCastleProvider.PROVIDER_NAME);
    assertNotNull(signature);

    // verify the signature
    Signature verifier =
        Signature.getInstance(DNSSEC.algString(algorithm), BouncyCastleProvider.PROVIDER_NAME);
    verifier.initVerify(keyPair.getPublic());
    verifier.update(toSign);
    boolean verify = verifier.verify(signature);
    assertTrue(verify);
  }
}
