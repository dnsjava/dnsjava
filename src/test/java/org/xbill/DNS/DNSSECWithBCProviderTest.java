package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.Algorithm;

public class DNSSECWithBCProviderTest {

  private static final String KEY_ALGORITHM = "RSA";
  int algorithm = Algorithm.RSASHA1;
  String bcJCAProvider = "BC";
  byte[] toSign = "The quick brown fox jumped over the lazy dog.".getBytes();

  @BeforeAll
  static void setUp() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void testSignWithDNSSECAndBCProvider() throws Exception {

    // generate a signature
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, bcJCAProvider);
    keyPairGenerator.initialize(512);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    byte[] signature =
        DNSSEC.sign(keyPair.getPrivate(), keyPair.getPublic(), algorithm, toSign, bcJCAProvider);
    assertNotNull(signature);

    // verify the signature
    Signature verifier = Signature.getInstance(DNSSEC.algString(algorithm), bcJCAProvider);
    verifier.initVerify(keyPair.getPublic());
    verifier.update(toSign);
    boolean verify = verifier.verify(signature);
    assertTrue(verify);
  }
}
