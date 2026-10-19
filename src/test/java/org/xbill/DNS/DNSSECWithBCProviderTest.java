// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.DNSSEC.Digest;
import org.xbill.DNS.utils.base16;

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

  @Test
  void testGenerateDSDigestGost2012() throws IOException {
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                Name.fromConstantString("example."),
                Type.DNSKEY,
                DClass.IN,
                3600,
                "257 3 23 p8Req8DLJOfPymO5vExuK4gCcihF5N1YL7veCJ47av+wh/qs9yJpD064k02rYUHfWnr7IjvJlbn3Z0sTZe9GRQ==",
                Name.root);
    byte[] expectedDigest =
        base16.fromString("6033725b0ccfc05d1e9d844d49c6cf890b13d5eac9439189947d5db6c8d1c1ec");
    assertArrayEquals(expectedDigest, DNSSEC.generateDSDigest(dnskey, Digest.GOST3411_12));
  }
}
