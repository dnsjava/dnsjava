// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2010 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Constants and methods relating to DNSSEC.
 *
 * <p>DNSSEC provides authentication for DNS information.
 *
 * @author Brian Wellington
 * @see RRSIGRecord
 * @see DNSKEYRecord
 * @see RRset
 */
public class DNSSEC {
  /** Domain Name System Security (DNSSEC) Algorithm Numbers. */
  public static class Algorithm {
    private Algorithm() {}

    /**
     * Delete DS record in parent zone, RFC8078.
     *
     * @since 3.5
     */
    public static final int DELETE = 0;

    /** RSA/MD5 public key (deprecated) */
    public static final int RSAMD5 = 1;

    /** Diffie Hellman key */
    public static final int DH = 2;

    /** DSA public key */
    public static final int DSA = 3;

    /** RSA/SHA1 public key */
    public static final int RSASHA1 = 5;

    /** DSA/SHA1, NSEC3-aware public key */
    public static final int DSA_NSEC3_SHA1 = 6;

    /** RSA/SHA1, NSEC3-aware public key */
    public static final int RSA_NSEC3_SHA1 = 7;

    /** RSA/SHA256 public key */
    public static final int RSASHA256 = 8;

    /** RSA/SHA512 public key */
    public static final int RSASHA512 = 10;

    /** GOST R 34.10-2001. This requires an external cryptography provider, such as BouncyCastle. */
    public static final int ECC_GOST = 12;

    /** ECDSA Curve P-256 with SHA-256 public key * */
    public static final int ECDSAP256SHA256 = 13;

    /** ECDSA Curve P-384 with SHA-384 public key * */
    public static final int ECDSAP384SHA384 = 14;

    /** Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC, RFC8080 */
    public static final int ED25519 = 15;

    /** Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC, RFC8080 */
    public static final int ED448 = 16;

    /** Indirect keys; the actual key is elsewhere. */
    public static final int INDIRECT = 252;

    /** Private algorithm, specified by domain name */
    public static final int PRIVATEDNS = 253;

    /** Private algorithm, specified by OID */
    public static final int PRIVATEOID = 254;

    private static final Mnemonic algs = new Mnemonic("DNSSEC algorithm", Mnemonic.CASE_UPPER);

    static {
      algs.setMaximum(0xFF);
      algs.setNumericAllowed(true);

      algs.add(DELETE, "DELETE");
      algs.add(RSAMD5, "RSAMD5");
      algs.add(DH, "DH");
      algs.add(DSA, "DSA");
      algs.add(RSASHA1, "RSASHA1");
      algs.add(DSA_NSEC3_SHA1, "DSA-NSEC3-SHA1");
      algs.add(RSA_NSEC3_SHA1, "RSA-NSEC3-SHA1");
      algs.add(RSASHA256, "RSASHA256");
      algs.add(RSASHA512, "RSASHA512");
      algs.add(ECC_GOST, "ECC-GOST");
      algs.add(ECDSAP256SHA256, "ECDSAP256SHA256");
      algs.add(ECDSAP384SHA384, "ECDSAP384SHA384");
      algs.add(ED25519, "ED25519");
      algs.add(ED448, "ED448");
      algs.add(INDIRECT, "INDIRECT");
      algs.add(PRIVATEDNS, "PRIVATEDNS");
      algs.add(PRIVATEOID, "PRIVATEOID");
    }

    /** Converts an algorithm into its textual representation */
    public static String string(int alg) {
      return algs.getText(alg);
    }

    /**
     * Converts a textual representation of an algorithm into its numeric code. Integers in the
     * range 0..255 are also accepted.
     *
     * @param s The textual representation of the algorithm
     * @return The algorithm code, or -1 on error.
     */
    public static int value(String s) {
      return algs.getValue(s);
    }
  }

  /**
   * DNSSEC Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms.
   *
   * @since 3.5
   */
  public static class Digest {
    private Digest() {}

    /** SHA-1, RFC3658. */
    public static final int SHA1 = 1;

    /** SHA-256, RFC4509. */
    public static final int SHA256 = 2;

    /** GOST R 34.11-94, RFC5933. */
    public static final int GOST3411 = 3;

    /** SHA-384, RFC6605. */
    public static final int SHA384 = 4;

    private static final Mnemonic algs =
        new Mnemonic("DNSSEC Digest Algorithm", Mnemonic.CASE_UPPER);
    private static final Map<Integer, Integer> algLengths = new HashMap<>(4);

    static {
      algs.setMaximum(0xFF);
      algs.setNumericAllowed(true);

      algs.add(SHA1, "SHA-1");
      algLengths.put(SHA1, 20);
      algs.add(SHA256, "SHA-256");
      algLengths.put(SHA256, 32);
      algs.add(GOST3411, "GOST R 34.11-94");
      algLengths.put(GOST3411, 32);
      algs.add(SHA384, "SHA-384");
      algLengths.put(SHA384, 48);
    }

    /** Converts an algorithm into its textual representation */
    public static String string(int alg) {
      return algs.getText(alg);
    }

    /**
     * Converts a textual representation of an algorithm into its numeric code. Integers in the
     * range 0..255 are also accepted.
     *
     * @param s The textual representation of the algorithm
     * @return The algorithm code, or -1 on error.
     */
    public static int value(String s) {
      return algs.getValue(s);
    }

    /**
     * Gets the length, in bytes, of the specified digest id.
     *
     * @return The length, in bytes, or -1 for an unknown digest.
     * @since 3.6
     */
    public static int algLength(int alg) {
      Integer len = algLengths.get(alg);
      return len == null ? -1 : len;
    }
  }

  private DNSSEC() {}

  private static void digestSIG(DNSOutput out, SIGBase sig) {
    out.writeU16(sig.getTypeCovered());
    out.writeU8(sig.getAlgorithm());
    out.writeU8(sig.getLabels());
    out.writeU32(sig.getOrigTTL());
    out.writeU32(sig.getExpire().getEpochSecond());
    out.writeU32(sig.getTimeSigned().getEpochSecond());
    out.writeU16(sig.getFootprint());
    sig.getSigner().toWireCanonical(out);
  }

  /**
   * Creates a byte array containing the concatenation of the fields of the SIG record and the
   * RRsets to be signed/verified. This does not perform a cryptographic digest.
   *
   * @param rrsig The RRSIG record used to sign/verify the rrset.
   * @param rrset The data to be signed/verified.
   * @return The data to be cryptographically signed or verified.
   */
  public static byte[] digestRRset(RRSIGRecord rrsig, RRset rrset) {
    DNSOutput out = new DNSOutput();
    digestSIG(out, rrsig);

    Name name = rrset.getName();
    Name wild = null;
    int sigLabels = rrsig.getLabels() + 1; // Add the root label back.
    if (name.labels() > sigLabels) {
      wild = name.wild(name.labels() - sigLabels);
    }

    DNSOutput header = new DNSOutput();
    if (wild != null) {
      wild.toWireCanonical(header);
    } else {
      name.toWireCanonical(header);
    }
    header.writeU16(rrset.getType());
    header.writeU16(rrset.getDClass());
    header.writeU32(rrsig.getOrigTTL());
    rrset.rrs(false).stream()
        .sorted()
        .forEachOrdered(
            r -> {
              out.writeByteArray(header.toByteArray());
              int lengthPosition = out.current();
              out.writeU16(0);
              r.rrToWire(out, null, true);
              int rrlength = out.current() - lengthPosition - 2;
              out.save();
              out.jump(lengthPosition);
              out.writeU16(rrlength);
              out.restore();
            });
    return out.toByteArray();
  }

  /**
   * Creates a byte array containing the concatenation of the fields of the SIG(0) record and the
   * message to be signed. This does not perform a cryptographic digest.
   *
   * @param sig The SIG record used to sign the rrset.
   * @param msg The message to be signed.
   * @param previous If this is a response, the signature from the query.
   * @return The data to be cryptographically signed.
   */
  public static byte[] digestMessage(SIGRecord sig, Message msg, byte[] previous) {
    DNSOutput out = new DNSOutput();
    digestSIG(out, sig);

    if (previous != null) {
      out.writeByteArray(previous);
    }

    msg.toWire(out);
    return out.toByteArray();
  }

  /** A DNSSEC exception. */
  public static class DNSSECException extends Exception {
    DNSSECException(String message, Throwable cause) {
      super(message, cause);
    }

    DNSSECException(Throwable cause) {
      super(cause);
    }

    DNSSECException(String message) {
      super(message);
    }
  }

  /** An algorithm is unsupported by this DNSSEC implementation. */
  public static class UnsupportedAlgorithmException extends DNSSECException {
    UnsupportedAlgorithmException(int alg) {
      super("Unsupported algorithm: " + alg);
    }
  }

  /** The cryptographic data in a DNSSEC key is malformed. */
  public static class MalformedKeyException extends DNSSECException {
    MalformedKeyException(String message) {
      super(message);
    }

    MalformedKeyException(Record rec, Throwable cause) {
      super("Invalid key data: " + rec.rdataToString(), cause);
    }
  }

  /** A DNSSEC verification failed because fields in the DNSKEY and RRSIG records do not match. */
  public static class KeyMismatchException extends DNSSECException {
    KeyMismatchException(KEYBase key, SIGBase sig) {
      super(
          "key "
              + key.getName()
              + "/"
              + DNSSEC.Algorithm.string(key.getAlgorithm())
              + "/"
              + key.getFootprint()
              + " "
              + "does not match signature "
              + sig.getSigner()
              + "/"
              + DNSSEC.Algorithm.string(sig.getAlgorithm())
              + "/"
              + sig.getFootprint());
    }
  }

  /** A DNSSEC verification failed because the signature has expired. */
  public static class SignatureExpiredException extends DNSSECException {
    private final Instant when;
    private final Instant now;

    SignatureExpiredException(Instant when, Instant now) {
      super("signature expired");
      this.when = when;
      this.now = now;
    }

    /** When the signature expired. */
    public Instant getExpiration() {
      return when;
    }

    /** When the verification was attempted. */
    public Instant getVerifyTime() {
      return now;
    }
  }

  /** A DNSSEC verification failed because the signature has not yet become valid. */
  public static class SignatureNotYetValidException extends DNSSECException {
    private final Instant when;
    private final Instant now;

    SignatureNotYetValidException(Instant when, Instant now) {
      super("signature is not yet valid");
      this.when = when;
      this.now = now;
    }

    /** When the signature will become valid. */
    public Instant getExpiration() {
      return when;
    }

    /** When the verification was attempted. */
    public Instant getVerifyTime() {
      return now;
    }
  }

  /** A DNSSEC verification failed because the cryptographic signature verification failed. */
  public static class SignatureVerificationException extends DNSSECException {
    SignatureVerificationException() {
      super("signature verification failed");
    }
  }

  /** The key data provided is inconsistent. */
  public static class IncompatibleKeyException extends IllegalArgumentException {
    IncompatibleKeyException() {
      super("incompatible keys");
    }
  }

  /** No signature was found. */
  public static class NoSignatureException extends DNSSECException {
    NoSignatureException() {
      super("no signature found");
    }
  }

  private static int bigIntegerLength(BigInteger i) {
    return (i.bitLength() + 7) / 8;
  }

  private static BigInteger readBigInteger(DNSInput in, int len) throws IOException {
    byte[] b = in.readByteArray(len);
    return new BigInteger(1, b);
  }

  private static BigInteger readBigInteger(DNSInput in) {
    byte[] b = in.readByteArray();
    return new BigInteger(1, b);
  }

  private static byte[] trimByteArray(byte[] array) {
    if (array[0] == 0) {
      byte[] trimmedArray = new byte[array.length - 1];
      System.arraycopy(array, 1, trimmedArray, 0, array.length - 1);
      return trimmedArray;
    } else {
      return array;
    }
  }

  private static void reverseByteArray(byte[] array) {
    for (int i = 0; i < array.length / 2; i++) {
      int j = array.length - i - 1;
      byte tmp = array[i];
      array[i] = array[j];
      array[j] = tmp;
    }
  }

  private static BigInteger readBigIntegerLittleEndian(DNSInput in, int len) throws IOException {
    byte[] b = in.readByteArray(len);
    reverseByteArray(b);
    return new BigInteger(1, b);
  }

  private static void writeBigInteger(DNSOutput out, BigInteger val) {
    byte[] b = trimByteArray(val.toByteArray());
    out.writeByteArray(b);
  }

  private static void writePaddedBigInteger(DNSOutput out, BigInteger val, int len) {
    byte[] b = trimByteArray(val.toByteArray());

    if (b.length > len) {
      throw new IllegalArgumentException();
    }

    if (b.length < len) {
      byte[] pad = new byte[len - b.length];
      out.writeByteArray(pad);
    }

    out.writeByteArray(b);
  }

  private static void writePaddedBigIntegerLittleEndian(DNSOutput out, BigInteger val, int len) {
    byte[] b = trimByteArray(val.toByteArray());

    if (b.length > len) {
      throw new IllegalArgumentException();
    }

    reverseByteArray(b);
    out.writeByteArray(b);

    if (b.length < len) {
      byte[] pad = new byte[len - b.length];
      out.writeByteArray(pad);
    }
  }

  private static PublicKey toRSAPublicKey(byte[] key) throws IOException, GeneralSecurityException {
    DNSInput in = new DNSInput(key);
    int exponentLength = in.readU8();
    if (exponentLength == 0) {
      exponentLength = in.readU16();
    }
    BigInteger exponent = readBigInteger(in, exponentLength);
    BigInteger modulus = readBigInteger(in);

    KeyFactory factory = KeyFactory.getInstance("RSA");
    return factory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
  }

  private static PublicKey toDSAPublicKey(byte[] key)
      throws IOException, GeneralSecurityException, MalformedKeyException {
    DNSInput in = new DNSInput(key);

    int t = in.readU8();
    if (t > 8) {
      throw new MalformedKeyException("t is too large");
    }

    BigInteger q = readBigInteger(in, 20);
    BigInteger p = readBigInteger(in, 64 + t * 8);
    BigInteger g = readBigInteger(in, 64 + t * 8);
    BigInteger y = readBigInteger(in, 64 + t * 8);

    KeyFactory factory = KeyFactory.getInstance("DSA");
    return factory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
  }

  private static class ECKeyInfo {
    int length;
    EllipticCurve curve;
    ECParameterSpec spec;

    ECKeyInfo(int length, String p, String a, String b, String gx, String gy, String n) {
      this.length = length;
      BigInteger pi = new BigInteger(p, 16);
      BigInteger ai = new BigInteger(a, 16);
      BigInteger bi = new BigInteger(b, 16);
      BigInteger gxi = new BigInteger(gx, 16);
      BigInteger gyi = new BigInteger(gy, 16);
      BigInteger ni = new BigInteger(n, 16);
      curve = new EllipticCurve(new ECFieldFp(pi), ai, bi);
      spec = new ECParameterSpec(curve, new ECPoint(gxi, gyi), ni, 1);
    }
  }

  // RFC 4357 Section 11.4
  private static final ECKeyInfo GOST =
      new ECKeyInfo(
          32,
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
          "A6",
          "1",
          "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893");

  // RFC 5114 Section 2.6
  private static final ECKeyInfo ECDSA_P256 =
      new ECKeyInfo(
          32,
          "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
          "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
          "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
          "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
          "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
          "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

  // RFC 5114 Section 2.7
  private static final ECKeyInfo ECDSA_P384 =
      new ECKeyInfo(
          48,
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
          "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
          "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
          "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");

  private static PublicKey toECGOSTPublicKey(byte[] key, ECKeyInfo keyinfo)
      throws IOException, GeneralSecurityException {
    DNSInput in = new DNSInput(key);

    BigInteger x = readBigIntegerLittleEndian(in, keyinfo.length);
    BigInteger y = readBigIntegerLittleEndian(in, keyinfo.length);
    ECPoint q = new ECPoint(x, y);

    KeyFactory factory = KeyFactory.getInstance("ECGOST3410");
    return factory.generatePublic(new ECPublicKeySpec(q, keyinfo.spec));
  }

  private static PublicKey toECDSAPublicKey(byte[] key, ECKeyInfo keyinfo)
      throws IOException, GeneralSecurityException {
    DNSInput in = new DNSInput(key);

    // RFC 6605 Section 4
    BigInteger x = readBigInteger(in, keyinfo.length);
    BigInteger y = readBigInteger(in, keyinfo.length);
    ECPoint q = new ECPoint(x, y);

    KeyFactory factory = KeyFactory.getInstance("EC");
    return factory.generatePublic(new ECPublicKeySpec(q, keyinfo.spec));
  }

  private static PublicKey toEdDSAPublicKey(byte[] key, byte algId)
      throws GeneralSecurityException {
    // Key is encoded as plain octets, rfc8080#section-3
    // wrap it in ASN.1 format so we can use X509EncodedKeySpec to read it as JCA
    byte[] encoded = new byte[12 + key.length];
    encoded[0] = ASN1_SEQ;
    encoded[1] = (byte) (10 + key.length); // length
    encoded[2] = ASN1_SEQ;
    encoded[3] = 5; // length
    encoded[4] = ASN1_OID; // OID
    encoded[5] = 3; // length
    encoded[6] = 0x2b; // iso.org
    encoded[7] = 0x65; // 101 thawte
    encoded[8] = algId;
    encoded[9] = ASN1_BITSTRING; // sequence
    encoded[10] = (byte) (key.length + 1); // length
    System.arraycopy(key, 0, encoded, 12, key.length);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
    KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
    return keyFactory.generatePublic(keySpec);
  }

  /** Converts a KEY/DNSKEY record into a PublicKey */
  static PublicKey toPublicKey(KEYBase r) throws DNSSECException {
    return toPublicKey(r.getAlgorithm(), r.getKey(), r);
  }

  /** Converts a KEY/DNSKEY record into a PublicKey */
  static PublicKey toPublicKey(int alg, byte[] key, Record r) throws DNSSECException {
    try {
      switch (alg) {
        case Algorithm.RSAMD5:
        case Algorithm.RSASHA1:
        case Algorithm.RSA_NSEC3_SHA1:
        case Algorithm.RSASHA256:
        case Algorithm.RSASHA512:
          return toRSAPublicKey(key);
        case Algorithm.DSA:
        case Algorithm.DSA_NSEC3_SHA1:
          return toDSAPublicKey(key);
        case Algorithm.ECC_GOST:
          return toECGOSTPublicKey(key, GOST);
        case Algorithm.ECDSAP256SHA256:
          return toECDSAPublicKey(key, ECDSA_P256);
        case Algorithm.ECDSAP384SHA384:
          return toECDSAPublicKey(key, ECDSA_P384);
        case Algorithm.ED25519:
          return toEdDSAPublicKey(key, (byte) 112);
        case Algorithm.ED448:
          return toEdDSAPublicKey(key, (byte) 113);
        default:
          throw new UnsupportedAlgorithmException(alg);
      }
    } catch (IOException e) {
      throw new MalformedKeyException(r, e);
    } catch (GeneralSecurityException e) {
      throw new DNSSECException(e);
    }
  }

  private static byte[] fromRSAPublicKey(RSAPublicKey key) {
    DNSOutput out = new DNSOutput();
    BigInteger exponent = key.getPublicExponent();
    BigInteger modulus = key.getModulus();
    int exponentLength = bigIntegerLength(exponent);

    if (exponentLength < 256) {
      out.writeU8(exponentLength);
    } else {
      out.writeU8(0);
      out.writeU16(exponentLength);
    }
    writeBigInteger(out, exponent);
    writeBigInteger(out, modulus);

    return out.toByteArray();
  }

  private static byte[] fromDSAPublicKey(DSAPublicKey key) {
    DNSOutput out = new DNSOutput();
    BigInteger q = key.getParams().getQ();
    BigInteger p = key.getParams().getP();
    BigInteger g = key.getParams().getG();
    BigInteger y = key.getY();
    int t = (p.toByteArray().length - 64) / 8;

    out.writeU8(t);
    writeBigInteger(out, q);
    writeBigInteger(out, p);
    writePaddedBigInteger(out, g, 8 * t + 64);
    writePaddedBigInteger(out, y, 8 * t + 64);

    return out.toByteArray();
  }

  private static byte[] fromECGOSTPublicKey(ECPublicKey key, ECKeyInfo keyinfo) {
    DNSOutput out = new DNSOutput();

    BigInteger x = key.getW().getAffineX();
    BigInteger y = key.getW().getAffineY();

    writePaddedBigIntegerLittleEndian(out, x, keyinfo.length);
    writePaddedBigIntegerLittleEndian(out, y, keyinfo.length);

    return out.toByteArray();
  }

  private static byte[] fromECDSAPublicKey(ECPublicKey key, ECKeyInfo keyinfo) {
    DNSOutput out = new DNSOutput();

    BigInteger x = key.getW().getAffineX();
    BigInteger y = key.getW().getAffineY();

    writePaddedBigInteger(out, x, keyinfo.length);
    writePaddedBigInteger(out, y, keyinfo.length);

    return out.toByteArray();
  }

  private static byte[] fromEdDSAPublicKey(PublicKey key) {
    // The key is a signed DER BitString, starting at index 10. Drop the leading zero if necessary
    byte[] encoded = key.getEncoded();
    return Arrays.copyOfRange(encoded, 12, encoded.length);
  }

  /** Builds a DNSKEY record from a PublicKey */
  static byte[] fromPublicKey(PublicKey key, int alg) throws DNSSECException {
    switch (alg) {
      case Algorithm.RSAMD5:
      case Algorithm.RSASHA1:
      case Algorithm.RSA_NSEC3_SHA1:
      case Algorithm.RSASHA256:
      case Algorithm.RSASHA512:
        if (!(key instanceof RSAPublicKey)) {
          throw new IncompatibleKeyException();
        }
        return fromRSAPublicKey((RSAPublicKey) key);
      case Algorithm.DSA:
      case Algorithm.DSA_NSEC3_SHA1:
        if (!(key instanceof DSAPublicKey)) {
          throw new IncompatibleKeyException();
        }
        return fromDSAPublicKey((DSAPublicKey) key);
      case Algorithm.ECC_GOST:
        if (!(key instanceof ECPublicKey)) {
          throw new IncompatibleKeyException();
        }
        return fromECGOSTPublicKey((ECPublicKey) key, GOST);
      case Algorithm.ECDSAP256SHA256:
        if (!(key instanceof ECPublicKey)) {
          throw new IncompatibleKeyException();
        }
        return fromECDSAPublicKey((ECPublicKey) key, ECDSA_P256);
      case Algorithm.ECDSAP384SHA384:
        if (!(key instanceof ECPublicKey)) {
          throw new IncompatibleKeyException();
        }
        return fromECDSAPublicKey((ECPublicKey) key, ECDSA_P384);
      case Algorithm.ED25519:
      case Algorithm.ED448:
        if (!key.getFormat().equalsIgnoreCase("X.509")) {
          throw new IncompatibleKeyException();
        }
        return fromEdDSAPublicKey(key);
      default:
        throw new UnsupportedAlgorithmException(alg);
    }
  }

  /**
   * Convert an algorithm number to the corresponding JCA string.
   *
   * @param alg The algorithm number.
   * @throws UnsupportedAlgorithmException The algorithm is unknown.
   */
  public static String algString(int alg) throws UnsupportedAlgorithmException {
    switch (alg) {
      case Algorithm.RSAMD5:
        return "MD5withRSA";
      case Algorithm.DSA:
      case Algorithm.DSA_NSEC3_SHA1:
        return "SHA1withDSA";
      case Algorithm.RSASHA1:
      case Algorithm.RSA_NSEC3_SHA1:
        return "SHA1withRSA";
      case Algorithm.RSASHA256:
        return "SHA256withRSA";
      case Algorithm.RSASHA512:
        return "SHA512withRSA";
      case Algorithm.ECC_GOST:
        return "GOST3411withECGOST3410";
      case Algorithm.ECDSAP256SHA256:
        return "SHA256withECDSA";
      case Algorithm.ECDSAP384SHA384:
        return "SHA384withECDSA";
      case Algorithm.ED25519:
        return "Ed25519";
      case Algorithm.ED448:
        return "Ed448";
      default:
        throw new UnsupportedAlgorithmException(alg);
    }
  }

  static final int ASN1_SEQ = 0x30;
  static final int ASN1_INT = 0x2;
  static final int ASN1_BITSTRING = 0x3;
  static final int ASN1_OID = 0x6;

  private static final int DSA_LEN = 20;

  private static IOException asn1ParseException(Object expected, Object actual) {
    return new IOException("Invalid ASN.1 data, expected " + expected + " got " + actual);
  }

  private static byte[] dsaSignatureFromDNS(byte[] signature, int keyLength, boolean skipT)
      throws DNSSECException, IOException {
    if (signature.length != keyLength * 2 + (skipT ? 1 : 0)) {
      throw new SignatureVerificationException();
    }

    DNSInput in = new DNSInput(signature);
    DNSOutput out = new DNSOutput();

    if (skipT) {
      // rfc2536#section-3, this applies to DSA only, not ECDSA
      in.readU8();
    }

    byte[] r = in.readByteArray(keyLength);
    int rlen = getDsaIntLen(r, keyLength);

    byte[] s = in.readByteArray(keyLength);
    int slen = getDsaIntLen(s, keyLength);

    out.writeU8(ASN1_SEQ);
    out.writeU8(rlen + slen + 4);

    writeAsn1Int(keyLength, out, r, rlen);
    writeAsn1Int(keyLength, out, s, slen);

    return out.toByteArray();
  }

  private static int getDsaIntLen(byte[] bigint, int dsaLen) {
    int len = dsaLen;
    if (bigint[0] < 0) {
      len++;
    } else {
      for (int i = 0; i < dsaLen - 1 && bigint[i] == 0 && bigint[i + 1] >= 0; i++) {
        len--;
      }
    }
    return len;
  }

  private static void writeAsn1Int(int keyLength, DNSOutput out, byte[] bigint, int bigintLen) {
    out.writeU8(ASN1_INT);
    out.writeU8(bigintLen);
    if (bigintLen > keyLength) {
      out.writeU8(0);
    }
    if (bigintLen >= keyLength) {
      out.writeByteArray(bigint);
    } else {
      out.writeByteArray(bigint, keyLength - bigintLen, bigintLen);
    }
  }

  private static byte[] dsaSignatureToDNS(byte[] signature, int rsLen, int t) throws IOException {
    DNSInput in = new DNSInput(signature);
    DNSOutput out = new DNSOutput();

    if (t > -1) {
      out.writeU8(t);
    }

    int tmp = in.readU8();
    if (tmp != ASN1_SEQ) {
      throw asn1ParseException(ASN1_SEQ, tmp);
    }
    /*int seqlen =*/ in.readU8();

    transformAns1IntToDns(rsLen, in, out);
    transformAns1IntToDns(rsLen, in, out);
    return out.toByteArray();
  }

  private static void transformAns1IntToDns(int rsLen, DNSInput in, DNSOutput out)
      throws IOException {
    int tmp = in.readU8();
    if (tmp != ASN1_INT) {
      throw asn1ParseException(ASN1_INT, tmp);
    }

    // the int must be of rsLen or +1 if it has a leading zero for negative
    // ASN.1 integers
    int len = in.readU8();
    if (len == rsLen + 1 && in.readU8() == 0) {
      --len;
    } else if (len <= rsLen) {
      // pad with leading zeros, rfc2536#section-3
      for (int i = 0; i < rsLen - len; i++) {
        out.writeU8(0);
      }
    } else {
      throw new IOException("Invalid r/s-value in ASN.1 DER encoded signature: " + len);
    }

    out.writeByteArray(in.readByteArray(len));
  }

  private static void verify(PublicKey key, int alg, byte[] data, byte[] signature)
      throws DNSSECException {
    if (key instanceof DSAPublicKey) {
      try {
        signature = dsaSignatureFromDNS(signature, DSA_LEN, true);
      } catch (IOException e) {
        throw new IllegalStateException();
      }
    } else if (key instanceof ECPublicKey) {
      try {
        switch (alg) {
          case Algorithm.ECC_GOST:
            // Wire format is equal to the engine input
            if (signature.length != GOST.length * 2) {
              throw new SignatureVerificationException();
            }
            break;
          case Algorithm.ECDSAP256SHA256:
            signature = dsaSignatureFromDNS(signature, ECDSA_P256.length, false);
            break;
          case Algorithm.ECDSAP384SHA384:
            signature = dsaSignatureFromDNS(signature, ECDSA_P384.length, false);
            break;
          default:
            throw new UnsupportedAlgorithmException(alg);
        }
      } catch (IOException e) {
        throw new IllegalStateException();
      }
    }

    try {
      Signature s = Signature.getInstance(algString(alg));
      s.initVerify(key);
      s.update(data);
      if (!s.verify(signature)) {
        throw new SignatureVerificationException();
      }
    } catch (GeneralSecurityException e) {
      throw new DNSSECException(e);
    }
  }

  private static boolean matches(SIGBase sig, KEYBase key) {
    return key.getAlgorithm() == sig.getAlgorithm()
        && key.getFootprint() == sig.getFootprint()
        && key.getName().equals(sig.getSigner());
  }

  /**
   * Verify a DNSSEC signature.
   *
   * @param rrset The data to be verified.
   * @param rrsig The RRSIG record containing the signature.
   * @param key The DNSKEY record to verify the signature with.
   * @throws UnsupportedAlgorithmException The algorithm is unknown
   * @throws MalformedKeyException The key is malformed
   * @throws KeyMismatchException The key and signature do not match
   * @throws SignatureExpiredException The signature has expired
   * @throws SignatureNotYetValidException The signature is not yet valid
   * @throws SignatureVerificationException The signature does not verify.
   * @throws DNSSECException Some other error occurred.
   */
  public static void verify(RRset rrset, RRSIGRecord rrsig, DNSKEYRecord key)
      throws DNSSECException {
    verify(rrset, rrsig, key, Instant.now());
  }

  /**
   * Verify a DNSSEC signature.
   *
   * @param rrset The data to be verified.
   * @param rrsig The RRSIG record containing the signature.
   * @param key The DNSKEY record to verify the signature with.
   * @param date The date against which the signature is verified.
   * @throws UnsupportedAlgorithmException The algorithm is unknown
   * @throws MalformedKeyException The key is malformed
   * @throws KeyMismatchException The key and signature do not match
   * @throws SignatureExpiredException The signature has expired
   * @throws SignatureNotYetValidException The signature is not yet valid
   * @throws SignatureVerificationException The signature does not verify.
   * @throws DNSSECException Some other error occurred.
   * @deprecated use {@link #verify(RRset, RRSIGRecord, DNSKEYRecord, Instant)}
   */
  @Deprecated
  public static void verify(RRset rrset, RRSIGRecord rrsig, DNSKEYRecord key, Date date)
      throws DNSSECException {
    verify(rrset, rrsig, key, date.toInstant());
  }

  /**
   * Verify a DNSSEC signature.
   *
   * @param rrset The data to be verified.
   * @param rrsig The RRSIG record containing the signature.
   * @param key The DNSKEY record to verify the signature with.
   * @param date The date against which the signature is verified.
   * @throws UnsupportedAlgorithmException The algorithm is unknown
   * @throws MalformedKeyException The key is malformed
   * @throws KeyMismatchException The key and signature do not match
   * @throws SignatureExpiredException The signature has expired
   * @throws SignatureNotYetValidException The signature is not yet valid
   * @throws SignatureVerificationException The signature does not verify.
   * @throws DNSSECException Some other error occurred.
   */
  public static void verify(RRset rrset, RRSIGRecord rrsig, DNSKEYRecord key, Instant date)
      throws DNSSECException {
    if (!matches(rrsig, key)) {
      throw new KeyMismatchException(key, rrsig);
    }

    if (date.compareTo(rrsig.getExpire()) > 0) {
      throw new SignatureExpiredException(rrsig.getExpire(), date);
    }
    if (date.compareTo(rrsig.getTimeSigned()) < 0) {
      throw new SignatureNotYetValidException(rrsig.getTimeSigned(), date);
    }

    verify(
        key.getPublicKey(), rrsig.getAlgorithm(),
        digestRRset(rrsig, rrset), rrsig.getSignature());
  }

  static byte[] sign(PrivateKey privkey, PublicKey pubkey, int alg, byte[] data, String provider)
      throws DNSSECException {
    byte[] signature;
    try {
      Signature s;
      if (provider != null) {
        s = Signature.getInstance(algString(alg), provider);
      } else {
        s = Signature.getInstance(algString(alg));
      }
      s.initSign(privkey);
      s.update(data);
      signature = s.sign();
    } catch (GeneralSecurityException e) {
      throw new DNSSECException(e);
    }

    if (pubkey instanceof DSAPublicKey) {
      try {
        DSAPublicKey dsa = (DSAPublicKey) pubkey;
        BigInteger p = dsa.getParams().getP();
        int t = (bigIntegerLength(p) - 64) / 8;
        signature = dsaSignatureToDNS(signature, DSA_LEN, t);
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
    } else if (pubkey instanceof ECPublicKey) {
      try {
        switch (alg) {
          case Algorithm.ECC_GOST:
            // Wire format is equal to the engine output
            break;
          case Algorithm.ECDSAP256SHA256:
            signature = dsaSignatureToDNS(signature, ECDSA_P256.length, -1);
            break;
          case Algorithm.ECDSAP384SHA384:
            signature = dsaSignatureToDNS(signature, ECDSA_P384.length, -1);
            break;
          default:
            throw new UnsupportedAlgorithmException(alg);
        }
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
    }

    return signature;
  }

  static void checkAlgorithm(PrivateKey key, int alg) throws UnsupportedAlgorithmException {
    switch (alg) {
      case Algorithm.RSAMD5:
      case Algorithm.RSASHA1:
      case Algorithm.RSA_NSEC3_SHA1:
      case Algorithm.RSASHA256:
      case Algorithm.RSASHA512:
        if (!"RSA".equals(key.getAlgorithm())) {
          throw new IncompatibleKeyException();
        }
        break;
      case Algorithm.DSA:
      case Algorithm.DSA_NSEC3_SHA1:
        if (!"DSA".equals(key.getAlgorithm())) {
          throw new IncompatibleKeyException();
        }
        break;
      case Algorithm.ECC_GOST:
      case Algorithm.ECDSAP256SHA256:
      case Algorithm.ECDSAP384SHA384:
        if (!"EC".equals(key.getAlgorithm()) && !"ECDSA".equals(key.getAlgorithm())) {
          throw new IncompatibleKeyException();
        }
        break;
      case Algorithm.ED25519:
        if (!"Ed25519".equals(key.getAlgorithm()) && !"EdDSA".equals(key.getAlgorithm())) {
          throw new IncompatibleKeyException();
        }
        break;
      case Algorithm.ED448:
        if (!"Ed448".equals(key.getAlgorithm()) && !"EdDSA".equals(key.getAlgorithm())) {
          throw new IncompatibleKeyException();
        }
        break;
      default:
        throw new UnsupportedAlgorithmException(alg);
    }
  }

  /**
   * Generate a DNSSEC signature. key and privateKey must refer to the same underlying cryptographic
   * key.
   *
   * @param rrset The data to be signed
   * @param key The DNSKEY record to use as part of signing
   * @param privkey The PrivateKey to use when signing
   * @param inception The time at which the signatures should become valid
   * @param expiration The time at which the signatures should expire
   * @return The generated signature
   * @throws UnsupportedAlgorithmException The algorithm is unknown
   * @throws MalformedKeyException The key is malformed
   * @throws DNSSECException Some other error occurred.
   * @deprecated use {@link #sign(RRset, DNSKEYRecord, PrivateKey, Instant, Instant)}
   */
  @Deprecated
  public static RRSIGRecord sign(
      RRset rrset, DNSKEYRecord key, PrivateKey privkey, Date inception, Date expiration)
      throws DNSSECException {
    return sign(rrset, key, privkey, inception.toInstant(), expiration.toInstant(), null);
  }

  /**
   * Generate a DNSSEC signature. key and privateKey must refer to the same underlying cryptographic
   * key.
   *
   * @param rrset The data to be signed
   * @param key The DNSKEY record to use as part of signing
   * @param privkey The PrivateKey to use when signing
   * @param inception The time at which the signatures should become valid
   * @param expiration The time at which the signatures should expire
   * @return The generated signature
   * @throws UnsupportedAlgorithmException The algorithm is unknown
   * @throws MalformedKeyException The key is malformed
   * @throws DNSSECException Some other error occurred.
   * @deprecated use {@link #sign(RRset, DNSKEYRecord, PrivateKey, Instant, Instant, String)}
   */
  @Deprecated
  public static RRSIGRecord sign(
      RRset rrset,
      DNSKEYRecord key,
      PrivateKey privkey,
      Date inception,
      Date expiration,
      String provider)
      throws DNSSECException {
    return sign(rrset, key, privkey, inception.toInstant(), expiration.toInstant(), provider);
  }

  /**
   * Generate a DNSSEC signature. key and privateKey must refer to the same underlying cryptographic
   * key.
   *
   * @param rrset The data to be signed
   * @param key The DNSKEY record to use as part of signing
   * @param privkey The PrivateKey to use when signing
   * @param inception The time at which the signatures should become valid
   * @param expiration The time at which the signatures should expire
   * @return The generated signature
   * @throws UnsupportedAlgorithmException The algorithm is unknown
   * @throws MalformedKeyException The key is malformed
   * @throws DNSSECException Some other error occurred.
   */
  public static RRSIGRecord sign(
      RRset rrset, DNSKEYRecord key, PrivateKey privkey, Instant inception, Instant expiration)
      throws DNSSECException {
    return sign(rrset, key, privkey, inception, expiration, null);
  }

  /**
   * Generate a DNSSEC signature. key and privateKey must refer to the same underlying cryptographic
   * key.
   *
   * @param rrset The data to be signed
   * @param key The DNSKEY record to use as part of signing
   * @param privkey The PrivateKey to use when signing
   * @param inception The time at which the signatures should become valid
   * @param expiration The time at which the signatures should expire
   * @param provider The name of the JCA provider. If non-null, it will be passed to JCA
   *     getInstance() methods.
   * @return The generated signature
   * @throws UnsupportedAlgorithmException The algorithm is unknown
   * @throws MalformedKeyException The key is malformed
   * @throws DNSSECException Some other error occurred.
   */
  public static RRSIGRecord sign(
      RRset rrset,
      DNSKEYRecord key,
      PrivateKey privkey,
      Instant inception,
      Instant expiration,
      String provider)
      throws DNSSECException {
    int alg = key.getAlgorithm();
    checkAlgorithm(privkey, alg);

    RRSIGRecord rrsig =
        new RRSIGRecord(
            rrset.getName(),
            rrset.getDClass(),
            rrset.getTTL(),
            rrset.getType(),
            alg,
            rrset.getTTL(),
            expiration,
            inception,
            key.getFootprint(),
            key.getName(),
            null);

    rrsig.setSignature(sign(privkey, key.getPublicKey(), alg, digestRRset(rrsig, rrset), provider));
    return rrsig;
  }

  static SIGRecord signMessage(
      Message message,
      SIGRecord previous,
      KEYRecord key,
      PrivateKey privkey,
      Instant inception,
      Instant expiration)
      throws DNSSECException {
    int alg = key.getAlgorithm();
    checkAlgorithm(privkey, alg);

    SIGRecord sig =
        new SIGRecord(
            Name.root,
            DClass.ANY,
            0,
            0,
            alg,
            0,
            expiration,
            inception,
            key.getFootprint(),
            key.getName(),
            null);
    DNSOutput out = new DNSOutput();
    digestSIG(out, sig);
    if (previous != null) {
      out.writeByteArray(previous.getSignature());
    }
    out.writeByteArray(message.toWire());

    sig.setSignature(sign(privkey, key.getPublicKey(), alg, out.toByteArray(), null));
    return sig;
  }

  static void verifyMessage(
      Message message, byte[] bytes, SIGRecord sig, SIGRecord previous, KEYRecord key, Instant now)
      throws DNSSECException {
    if (message.sig0start == 0) {
      throw new NoSignatureException();
    }

    if (!matches(sig, key)) {
      throw new KeyMismatchException(key, sig);
    }

    if (now.compareTo(sig.getExpire()) > 0) {
      throw new SignatureExpiredException(sig.getExpire(), now);
    }
    if (now.compareTo(sig.getTimeSigned()) < 0) {
      throw new SignatureNotYetValidException(sig.getTimeSigned(), now);
    }

    DNSOutput out = new DNSOutput();
    digestSIG(out, sig);
    if (previous != null) {
      out.writeByteArray(previous.getSignature());
    }

    Header header = message.getHeader().clone();
    header.decCount(Section.ADDITIONAL);
    out.writeByteArray(header.toWire());

    out.writeByteArray(bytes, Header.LENGTH, message.sig0start - Header.LENGTH);

    verify(
        key.getPublicKey(), sig.getAlgorithm(),
        out.toByteArray(), sig.getSignature());
  }

  /**
   * Generate the digest value for a DS key
   *
   * @param key Which is covered by the DS record
   * @param digestid The type of digest
   * @return The digest value as an array of bytes
   */
  static byte[] generateDSDigest(DNSKEYRecord key, int digestid) {
    MessageDigest digest;
    try {
      switch (digestid) {
        case Digest.SHA1:
          digest = MessageDigest.getInstance("sha-1");
          break;
        case Digest.SHA256:
          digest = MessageDigest.getInstance("sha-256");
          break;
        case Digest.GOST3411:
          digest = MessageDigest.getInstance("GOST3411");
          break;
        case Digest.SHA384:
          digest = MessageDigest.getInstance("sha-384");
          break;
        default:
          throw new IllegalArgumentException("unknown DS digest type " + digestid);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("no message digest support");
    }
    digest.update(key.getName().toWireCanonical());
    digest.update(key.rdataToWireCanonical());
    return digest.digest();
  }
}
