// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.util.function.Function;
import org.xbill.DNS.utils.base16;

/**
 * SSH Fingerprint - stores the fingerprint of an SSH host key.
 *
 * @author Brian Wellington
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4255">RFC 4255: Using DNS to Securely
 *     Publish Secure Shell (SSH) Key Fingerprints</a>
 */
public class SSHFPRecord extends Record {
  public static class Algorithm {
    private Algorithm() {}

    public static final int RSA = 1;
    public static final int DSS = 2;
  }

  public static class Digest {
    private Digest() {}

    public static final int SHA1 = 1;
  }

  private int alg;
  private int digestType;
  private byte[] fingerprint;

  SSHFPRecord() {}

  /**
   * Creates an SSHFP Record from the given data.
   *
   * @param alg The public key's algorithm.
   * @param digestType The public key's digest type.
   * @param fingerprint The public key's fingerprint.
   */
  public SSHFPRecord(Name name, int dclass, long ttl, int alg, int digestType, byte[] fingerprint) {
    super(name, Type.SSHFP, dclass, ttl);
    this.alg = checkU8("alg", alg);
    this.digestType = checkU8("digestType", digestType);
    this.fingerprint = fingerprint;
    validateFingerprintLength(IllegalArgumentException::new);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    alg = in.readU8();
    digestType = in.readU8();
    fingerprint = in.readByteArray();
    validateFingerprintLength(WireParseException::new);
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    alg = st.getUInt8();
    digestType = st.getUInt8();
    fingerprint = st.getHex(true);
    validateFingerprintLength(st::exception);
  }

  private <T extends Throwable> void validateFingerprintLength(Function<String, T> exceptionCreator)
      throws T {
    int expectedLength = fingerprintLength(digestType);
    if (expectedLength >= 0 && fingerprint.length != expectedLength) {
      throw exceptionCreator.apply(
          "Expected " + expectedLength + " fingerprint bytes, got " + fingerprint.length);
    }
  }

  private static int fingerprintLength(int digestType) {
    switch (digestType) {
      case Digest.SHA1:
        return 20;
      case 2:
        return 32;
      default:
        return -1;
    }
  }

  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(alg);
    sb.append(" ");
    sb.append(digestType);
    sb.append(" ");
    sb.append(base16.toString(fingerprint));
    return sb.toString();
  }

  /** Returns the public key's algorithm. */
  public int getAlgorithm() {
    return alg;
  }

  /** Returns the public key's digest type. */
  public int getDigestType() {
    return digestType;
  }

  /** Returns the fingerprint */
  public byte[] getFingerPrint() {
    return fingerprint;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU8(alg);
    out.writeU8(digestType);
    out.writeByteArray(fingerprint);
  }
}
