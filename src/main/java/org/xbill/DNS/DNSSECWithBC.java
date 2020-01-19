// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.DNSSEC.IncompatibleKeyException;
import org.xbill.DNS.DNSSEC.UnsupportedAlgorithmException;

/**
 * Utility class for EdDSA signatures. Keep separate from {@link DNSSEC} to keep BouncyCastle
 * optional until JEP 339 is available in Java.
 */
class DNSSECWithBC {
  static PublicKey toPublicKey(int alg, byte[] key)
      throws DNSSECException, GeneralSecurityException, IOException {
    switch (alg) {
      case Algorithm.ED25519:
        return toEdDSAPublicKey(key, EdECObjectIdentifiers.id_Ed25519);
      case Algorithm.ED448:
        return toEdDSAPublicKey(key, EdECObjectIdentifiers.id_Ed448);
      default:
        throw new UnsupportedAlgorithmException(alg);
    }
  }

  static byte[] fromPublicKey(PublicKey key, int alg) throws DNSSECException {
    switch (alg) {
      case Algorithm.ED25519:
      case Algorithm.ED448:
        if (!(key instanceof BCEdDSAPublicKey) || !key.getFormat().equalsIgnoreCase("X.509")) {
          throw new IncompatibleKeyException();
        }
        return fromEdDSAPublicKey(key);
      default:
        throw new UnsupportedAlgorithmException(alg);
    }
  }

  private static PublicKey toEdDSAPublicKey(byte[] key, ASN1ObjectIdentifier algId)
      throws GeneralSecurityException, IOException {
    // Key is encoded as plain octets, rfc8080#section-3
    // wrap it in ASN.1 format so we can use X509EncodedKeySpec to read it as JCA
    SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(algId), key);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyInfo.getEncoded());

    KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
    return keyFactory.generatePublic(keySpec);
  }

  private static byte[] fromEdDSAPublicKey(PublicKey key) {
    DNSOutput out = new DNSOutput();
    byte[] encoded = key.getEncoded();
    // subtract the X.509 prefix length
    out.writeByteArray(encoded, 12, encoded.length - 12);
    return out.toByteArray();
  }
}
