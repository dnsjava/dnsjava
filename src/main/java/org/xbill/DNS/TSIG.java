// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.utils.base64;
import org.xbill.DNS.utils.hexdump;

/**
 * Transaction signature handling. This class generates and verifies TSIG records on messages, which
 * provide transaction security.
 *
 * @see TSIGRecord
 * @author Brian Wellington
 */
@Slf4j
public class TSIG {
  // https://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xml

  /** The domain name representing the gss-tsig algorithm. */
  public static final Name GSS_TSIG = Name.fromConstantString("gss-tsig.");

  /** The domain name representing the HMAC-MD5 algorithm. */
  public static final Name HMAC_MD5 = Name.fromConstantString("HMAC-MD5.SIG-ALG.REG.INT.");

  /**
   * The domain name representing the HMAC-MD5 algorithm.
   *
   * @deprecated use {@link #HMAC_MD5}
   */
  @Deprecated public static final Name HMAC = HMAC_MD5;

  /** The domain name representing the HMAC-SHA1 algorithm. */
  public static final Name HMAC_SHA1 = Name.fromConstantString("hmac-sha1.");

  /** The domain name representing the HMAC-SHA224 algorithm. */
  public static final Name HMAC_SHA224 = Name.fromConstantString("hmac-sha224.");

  /** The domain name representing the HMAC-SHA256 algorithm. */
  public static final Name HMAC_SHA256 = Name.fromConstantString("hmac-sha256.");

  /** The domain name representing the HMAC-SHA384 algorithm. */
  public static final Name HMAC_SHA384 = Name.fromConstantString("hmac-sha384.");

  /** The domain name representing the HMAC-SHA512 algorithm. */
  public static final Name HMAC_SHA512 = Name.fromConstantString("hmac-sha512.");

  private static final Map<Name, String> algMap;

  static {
    Map<Name, String> out = new HashMap<>();
    out.put(HMAC_MD5, "HmacMD5");
    out.put(HMAC_SHA1, "HmacSHA1");
    out.put(HMAC_SHA224, "HmacSHA224");
    out.put(HMAC_SHA256, "HmacSHA256");
    out.put(HMAC_SHA384, "HmacSHA384");
    out.put(HMAC_SHA512, "HmacSHA512");
    algMap = Collections.unmodifiableMap(out);
  }

  /**
   * Convert an algorithm String to its equivalent Name.
   *
   * @param alg String containing name of algorithm.
   * @return Name object for algorithm
   * @throws IllegalArgumentException The algorithm is null or invalid.
   */
  public static Name algorithmToName(String alg) {
    if (alg == null) {
      throw new IllegalArgumentException("Null algorithm");
    }

    // Special case.  Allow "HMAC-MD5" as an alias
    // for the RFC name.
    if (alg.equalsIgnoreCase("HMAC-MD5") || alg.equalsIgnoreCase("HMAC-MD5.")) {
      return HMAC_MD5;
    }

    // Search through the RFC Names in the map and match
    // if the algorithm name with or without the trailing dot.
    // The match is case-insensitive.
    return algMap.keySet().stream()
        .filter(n -> n.toString().equalsIgnoreCase(alg) || n.toString(true).equalsIgnoreCase(alg))
        .findAny()
        .orElseGet(
            () ->
                // Did not find an RFC name, so fall through
                // and try the java names in the value of each
                // entry.  If not found after all this, then
                // throw an exception.
                algMap.entrySet().stream()
                    .filter(e -> e.getValue().equalsIgnoreCase(alg))
                    .map(Map.Entry::getKey)
                    .findAny()
                    .orElseThrow(() -> new IllegalArgumentException("Unknown algorithm: " + alg)));
  }

  /**
   * Convert an algorithm Name to a string.
   *
   * @param name Name object
   * @return String equivalent
   * @deprecated Returns java algorithm name, will be made private in 4.0
   */
  @Deprecated
  public static String nameToAlgorithm(Name name) {
    String alg = algMap.get(name);
    if (alg != null) {
      return alg;
    }
    throw new IllegalArgumentException("Unknown algorithm: " + name);
  }

  /** The default fudge value for outgoing packets. Can be overridden by the tsigfudge option. */
  public static final Duration FUDGE = Duration.ofSeconds(300);

  private final Name alg;
  private final Clock clock;
  private final Name name;
  private final SecretKey macKey;
  private final String macAlgorithm;
  private final Mac sharedHmac;

  /**
   * Verifies the data (computes the secure hash and compares it to the input)
   *
   * @param expected The expected (locally calculated) signature
   * @param signature The signature to compare against
   * @return true if the signature matches, false otherwise
   */
  private static boolean verify(byte[] expected, byte[] signature) {
    if (signature.length < expected.length) {
      byte[] truncated = new byte[signature.length];
      System.arraycopy(expected, 0, truncated, 0, truncated.length);
      expected = truncated;
    }
    return Arrays.equals(signature, expected);
  }

  private Mac initHmac() {
    if (sharedHmac != null) {
      try {
        return (Mac) sharedHmac.clone();
      } catch (CloneNotSupportedException e) {
        sharedHmac.reset();
        return sharedHmac;
      }
    }

    try {
      Mac mac = Mac.getInstance(macAlgorithm);
      mac.init(macKey);
      return mac;
    } catch (GeneralSecurityException ex) {
      throw new IllegalArgumentException("Caught security exception setting up HMAC.", ex);
    }
  }

  /**
   * Creates a new TSIG object, which can be used to sign or verify a message.
   *
   * @param name The name of the shared key.
   * @param key The shared key's data represented as a base64 encoded string.
   * @throws IllegalArgumentException The key name is an invalid name
   * @throws IllegalArgumentException The key data is improperly encoded
   * @throws NullPointerException key is null
   * @since 3.2
   */
  public TSIG(Name algorithm, Name name, String key) {
    this(algorithm, name, Objects.requireNonNull(base64.fromString(key)));
  }

  /**
   * Creates a new TSIG key, which can be used to sign or verify a message.
   *
   * @param algorithm The algorithm of the shared key.
   * @param name The name of the shared key.
   * @param keyBytes The shared key's data.
   */
  public TSIG(Name algorithm, Name name, byte[] keyBytes) {
    this(algorithm, name, new SecretKeySpec(keyBytes, nameToAlgorithm(algorithm)));
  }

  /**
   * Creates a new TSIG key, which can be used to sign or verify a message.
   *
   * @param algorithm The algorithm of the shared key.
   * @param name The name of the shared key.
   * @param key The shared key.
   */
  public TSIG(Name algorithm, Name name, SecretKey key) {
    this(algorithm, name, key, Clock.systemUTC());
  }

  /**
   * Creates a new TSIG key, which can be used to sign or verify a message.
   *
   * @param algorithm The algorithm of the shared key.
   * @param name The name of the shared key.
   * @param key The shared key.
   * @since 3.2
   */
  public TSIG(Name algorithm, Name name, SecretKey key, Clock clock) {
    this.name = name;
    this.alg = algorithm;
    this.clock = clock;
    this.macAlgorithm = nameToAlgorithm(algorithm);
    this.macKey = key;
    this.sharedHmac = null;
  }

  /**
   * Creates a new TSIG key from a pre-initialized Mac instance. This assumes that init() has
   * already been called on the mac to set up the key.
   *
   * @param mac The JCE HMAC object
   * @param name The name of the key
   * @deprecated Use one of the constructors that specifies an algorithm and key.
   */
  @Deprecated
  public TSIG(Mac mac, Name name) {
    this.name = name;
    this.sharedHmac = mac;
    this.macAlgorithm = null;
    this.macKey = null;
    this.clock = Clock.systemUTC();
    this.alg = algorithmToName(mac.getAlgorithm());
  }

  /**
   * Creates a new TSIG key with the {@link #HMAC_MD5} algorithm, which can be used to sign or
   * verify a message.
   *
   * @param name The name of the shared key.
   * @param key The shared key's data.
   * @deprecated Use {@link #TSIG(Name, Name, SecretKey)} to explicitly specify an algorithm.
   */
  @Deprecated
  public TSIG(Name name, byte[] key) {
    this(HMAC_MD5, name, key);
  }

  /**
   * Creates a new TSIG object, which can be used to sign or verify a message.
   *
   * @param name The name of the shared key.
   * @param key The shared key's data represented as a base64 encoded string.
   * @throws IllegalArgumentException The key name is an invalid name
   * @throws IllegalArgumentException The key data is improperly encoded
   */
  public TSIG(Name algorithm, String name, String key) {
    byte[] keyBytes = base64.fromString(key);
    if (keyBytes == null) {
      throw new IllegalArgumentException("Invalid TSIG key string");
    }
    try {
      this.name = Name.fromString(name, Name.root);
    } catch (TextParseException e) {
      throw new IllegalArgumentException("Invalid TSIG key name");
    }
    this.alg = algorithm;
    this.clock = Clock.systemUTC();
    this.macAlgorithm = nameToAlgorithm(algorithm);
    this.sharedHmac = null;
    this.macKey = new SecretKeySpec(keyBytes, macAlgorithm);
  }

  /**
   * Creates a new TSIG object, which can be used to sign or verify a message.
   *
   * @param algorithm The RFC8945 algorithm name of the shared key. The legal values are:
   *     <ul>
   *       <li>hmac-md5.sig-alg.reg.int.
   *       <li>hmac-md5. (alias for hmac-md5.sig-alg.reg.int.)
   *       <li>hmac-sha1.
   *       <li>hmac-sha224.
   *       <li>hmac-sha256.
   *       <li>hmac-sha384.
   *       <li>hmac-sha512.
   *     </ul>
   *     The trailing &quot;.&quot; can be omitted.
   * @param name The name of the shared key.
   * @param key The shared key's data represented as a base64 encoded string.
   * @throws IllegalArgumentException The key name is an invalid name
   * @throws IllegalArgumentException The key data is improperly encoded
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8945">RFC8945</a>
   */
  public TSIG(String algorithm, String name, String key) {
    this(algorithmToName(algorithm), name, key);
  }

  /**
   * Creates a new TSIG object with the {@link #HMAC_MD5} algorithm, which can be used to sign or
   * verify a message.
   *
   * @param name The name of the shared key
   * @param key The shared key's data, represented as a base64 encoded string.
   * @throws IllegalArgumentException The key name is an invalid name
   * @throws IllegalArgumentException The key data is improperly encoded
   * @deprecated Use {@link #TSIG(Name, String, String)} to explicitly specify an algorithm.
   */
  @Deprecated
  public TSIG(String name, String key) {
    this(HMAC_MD5, name, key);
  }

  /**
   * Creates a new TSIG object, which can be used to sign or verify a message.
   *
   * @param str The TSIG key, in the form name:secret, name/secret, alg:name:secret, or
   *     alg/name/secret. If no algorithm is specified, the default of {@link #HMAC_MD5} is used.
   * @throws IllegalArgumentException The string does not contain both a name and secret.
   * @throws IllegalArgumentException The key name is an invalid name
   * @throws IllegalArgumentException The key data is improperly encoded
   * @deprecated Use an explicit constructor
   */
  @Deprecated
  public static TSIG fromString(String str) {
    String[] parts = str.split("[:/]", 3);
    switch (parts.length) {
      case 2:
        return new TSIG(HMAC_MD5, parts[0], parts[1]);
      case 3:
        return new TSIG(parts[0], parts[1], parts[2]);
      default:
        throw new IllegalArgumentException("Invalid TSIG key specification");
    }
  }

  /**
   * Generates a TSIG record with a specific error for a message that has been rendered.
   *
   * @param m The message
   * @param b The rendered message
   * @param error The error
   * @param old If this message is a response, the TSIG from the request
   * @return The TSIG record to be added to the message
   */
  public TSIGRecord generate(Message m, byte[] b, int error, TSIGRecord old) {
    return generate(m, b, error, old, true);
  }

  /**
   * Generates a TSIG record with a specific error for a message that has been rendered.
   *
   * @param m The message
   * @param b The rendered message
   * @param error The error
   * @param old If this message is a response, the TSIG from the request
   * @param fullSignature {@code true} if this {@link TSIGRecord} is the to be added to the first of
   *     many messages in a TCP connection and all TSIG variables (rfc2845, 3.4.2.) should be
   *     included in the signature. {@code false} for subsequent messages with reduced TSIG
   *     variables set (rfc2845, 4.4.).
   * @return The TSIG record to be added to the message
   * @since 3.2
   */
  public TSIGRecord generate(
      Message m, byte[] b, int error, TSIGRecord old, boolean fullSignature) {
    Mac hmac = null;
    if (error == Rcode.NOERROR || error == Rcode.BADTIME || error == Rcode.BADTRUNC) {
      hmac = initHmac();
    }

    return generate(m, b, error, old, fullSignature, hmac);
  }

  /**
   * Generates a TSIG record with a specific error for a message that has been rendered.
   *
   * @param m The message
   * @param b The rendered message
   * @param error The error
   * @param old If this message is a response, the TSIG from the request
   * @param fullSignature {@code true} if this {@link TSIGRecord} is the to be added to the first of
   *     many messages in a TCP connection and all TSIG variables (rfc2845, 3.4.2.) should be
   *     included in the signature. {@code false} for subsequent messages with reduced TSIG
   *     variables set (rfc2845, 4.4.).
   * @param hmac A mac instance to reuse for a stream of messages to sign, e.g. when doing a zone
   *     transfer.
   * @return The TSIG record to be added to the message
   */
  private TSIGRecord generate(
      Message m, byte[] b, int error, TSIGRecord old, boolean fullSignature, Mac hmac) {
    Instant timeSigned = getTimeSigned(error, old);
    Duration fudge = getTsigFudge();

    boolean signing = hmac != null;
    if (old != null && signing) {
      hmacAddSignature(hmac, old);
    }

    // Digest the message
    if (signing) {
      if (log.isTraceEnabled()) {
        log.trace(hexdump.dump("TSIG-HMAC rendered message", b));
      }
      hmac.update(b);
    }

    // rfc2845, 3.4.2 TSIG Variables
    // for section 4.4 TSIG on TCP connection: skip name, class, ttl, alg and other
    DNSOutput out = new DNSOutput();
    if (fullSignature) {
      name.toWireCanonical(out);
      out.writeU16(DClass.ANY); /* class */
      out.writeU32(0); /* ttl */
      alg.toWireCanonical(out);
    }

    writeTsigTimerVariables(timeSigned, fudge, out);
    if (fullSignature) {
      out.writeU16(error);
      out.writeU16(0); /* No other data */
    }

    byte[] signature;
    if (signing) {
      byte[] tsigVariables = out.toByteArray();
      if (log.isTraceEnabled()) {
        log.trace(hexdump.dump("TSIG-HMAC variables", tsigVariables));
      }
      signature = hmac.doFinal(tsigVariables);
    } else {
      signature = new byte[0];
    }

    byte[] other = null;
    if (error == Rcode.BADTIME) {
      out = new DNSOutput(6);
      writeTsigTime(clock.instant(), out);
      other = out.toByteArray();
    }

    return new TSIGRecord(
        name,
        DClass.ANY,
        0,
        alg,
        timeSigned,
        fudge,
        signature,
        m.getHeader().getID(),
        error,
        other);
  }

  private Instant getTimeSigned(int error, TSIGRecord old) {
    return error == Rcode.BADTIME ? old.getTimeSigned() : clock.instant();
  }

  private static Duration getTsigFudge() {
    int fudgeOption = Options.intValue("tsigfudge");
    return fudgeOption < 0 || fudgeOption > 0x7FFF ? FUDGE : Duration.ofSeconds(fudgeOption);
  }

  /**
   * Generates a TSIG record for a message and adds it to the message
   *
   * @param m The message
   * @param old If this message is a response, the TSIG from the request
   */
  public void apply(Message m, TSIGRecord old) {
    apply(m, Rcode.NOERROR, old, true);
  }

  /**
   * Generates a TSIG record with a specific error for a message and adds it to the message.
   *
   * @param m The message
   * @param error The error
   * @param old If this message is a response, the TSIG from the request
   */
  public void apply(Message m, int error, TSIGRecord old) {
    apply(m, error, old, true);
  }

  /**
   * Generates a TSIG record with a specific error for a message and adds it to the message.
   *
   * @param m The message
   * @param old If this message is a response, the TSIG from the request
   * @param fullSignature {@code true} if this message is the first of many in a TCP connection and
   *     all TSIG variables (rfc2845, 3.4.2.) should be included in the signature. {@code false} for
   *     subsequent messages with reduced TSIG variables set (rfc2845, 4.4.).
   * @since 3.2
   */
  public void apply(Message m, TSIGRecord old, boolean fullSignature) {
    apply(m, Rcode.NOERROR, old, fullSignature);
  }

  /**
   * Generates a TSIG record with a specific error for a message and adds it to the message.
   *
   * @param m The message
   * @param error The error
   * @param old If this message is a response, the TSIG from the request
   * @param fullSignature {@code true} if this message is the first of many in a TCP connection and
   *     all TSIG variables (rfc2845, 3.4.2.) should be included in the signature. {@code false} for
   *     subsequent messages with reduced TSIG variables set (rfc2845, 4.4.).
   * @since 3.2
   */
  public void apply(Message m, int error, TSIGRecord old, boolean fullSignature) {
    Record r = generate(m, m.toWire(), error, old, fullSignature);
    m.addRecord(r, Section.ADDITIONAL);
    m.tsigState = Message.TSIG_SIGNED;
  }

  /**
   * Generates a TSIG record for a message and adds it to the message
   *
   * @param m The message
   * @param old If this message is a response, the TSIG from the request
   * @param fullSignature {@code true} if this message is the first of many in a TCP connection and
   *     all TSIG variables (rfc2845, 3.4.2.) should be included in the signature. {@code false} for
   *     subsequent messages with reduced TSIG variables set (rfc2845, 4.4.).
   * @deprecated use {@link #apply(Message, TSIGRecord, boolean)}
   */
  @Deprecated
  public void applyStream(Message m, TSIGRecord old, boolean fullSignature) {
    apply(m, Rcode.NOERROR, old, fullSignature);
  }

  /**
   * Verifies a TSIG record on an incoming message. Since this is only called in the context where a
   * TSIG is expected to be present, it is an error if one is not present. After calling this
   * routine, Message.isVerified() may be called on this message.
   *
   * <p>Use {@link StreamVerifier} to validate multiple messages in a stream.
   *
   * @param m The message
   * @param b An array containing the message in unparsed form. This is necessary since TSIG signs
   *     the message in wire format, and we can't recreate the exact wire format (with the same name
   *     compression).
   * @param length unused
   * @param old If this message is a response, the TSIG from the request
   * @return The result of the verification (as an Rcode)
   * @see Rcode
   * @deprecated use {@link #verify(Message, byte[], TSIGRecord)}
   */
  @Deprecated
  public byte verify(Message m, byte[] b, int length, TSIGRecord old) {
    return (byte) verify(m, b, old);
  }

  /**
   * Verifies a TSIG record on an incoming message. Since this is only called in the context where a
   * TSIG is expected to be present, it is an error if one is not present. After calling this
   * routine, Message.isVerified() may be called on this message.
   *
   * <p>Use {@link StreamVerifier} to validate multiple messages in a stream.
   *
   * @param m The message to verify
   * @param messageBytes An array containing the message in unparsed form. This is necessary since
   *     TSIG signs the message in wire format, and we can't recreate the exact wire format (with
   *     the same name compression).
   * @param requestTSIG If this message is a response, the TSIG from the request
   * @return The result of the verification (as an Rcode)
   * @see Rcode
   */
  public int verify(Message m, byte[] messageBytes, TSIGRecord requestTSIG) {
    return verify(m, messageBytes, requestTSIG, true);
  }

  /**
   * Verifies a TSIG record on an incoming message. Since this is only called in the context where a
   * TSIG is expected to be present, it is an error if one is not present. After calling this
   * routine, Message.isVerified() may be called on this message.
   *
   * <p>Use {@link StreamVerifier} to validate multiple messages in a stream.
   *
   * @param m The message to verify
   * @param messageBytes An array containing the message in unparsed form. This is necessary since
   *     TSIG signs the message in wire format, and we can't recreate the exact wire format (with
   *     the same name compression).
   * @param requestTSIG If this message is a response, the TSIG from the request
   * @param fullSignature {@code true} if this message is the first of many in a TCP connection and
   *     all TSIG variables (rfc2845, 3.4.2.) should be included in the signature. {@code false} for
   *     subsequent messages with reduced TSIG variables set (rfc2845, 4.4.).
   * @return The result of the verification (as an Rcode)
   * @see Rcode
   * @since 3.2
   */
  public int verify(Message m, byte[] messageBytes, TSIGRecord requestTSIG, boolean fullSignature) {
    return verify(m, messageBytes, requestTSIG, fullSignature, null);
  }

  /**
   * Verifies a TSIG record on an incoming message. Since this is only called in the context where a
   * TSIG is expected to be present, it is an error if one is not present. After calling this
   * routine, Message.isVerified() may be called on this message.
   *
   * @param m The message to verify
   * @param messageBytes An array containing the message in unparsed form. This is necessary since
   *     TSIG signs the message in wire format, and we can't recreate the exact wire format (with
   *     the same name compression).
   * @param requestTSIG If this message is a response, the TSIG from the request
   * @param fullSignature {@code true} if this message is the first of many in a TCP connection and
   *     all TSIG variables (rfc2845, 3.4.2.) should be included in the signature. {@code false} for
   *     subsequent messages with reduced TSIG variables set (rfc2845, 4.4.).
   * @return The result of the verification (as an Rcode)
   * @see Rcode
   */
  private int verify(
      Message m, byte[] messageBytes, TSIGRecord requestTSIG, boolean fullSignature, Mac hmac) {
    m.tsigState = Message.TSIG_FAILED;
    TSIGRecord tsig = m.getTSIG();
    if (tsig == null) {
      return Rcode.FORMERR;
    }

    if (!tsig.getName().equals(name) || !tsig.getAlgorithm().equals(alg)) {
      log.debug(
          "BADKEY failure on message id {}, expected: {}/{}, actual: {}/{}",
          m.getHeader().getID(),
          name,
          alg,
          tsig.getName(),
          tsig.getAlgorithm());
      return Rcode.BADKEY;
    }

    if (hmac == null) {
      hmac = initHmac();
    }

    if (requestTSIG != null && tsig.getError() != Rcode.BADKEY && tsig.getError() != Rcode.BADSIG) {
      hmacAddSignature(hmac, requestTSIG);
    }

    m.getHeader().decCount(Section.ADDITIONAL);
    byte[] header = m.getHeader().toWire();
    m.getHeader().incCount(Section.ADDITIONAL);
    if (log.isTraceEnabled()) {
      log.trace(hexdump.dump("TSIG-HMAC header", header));
    }
    hmac.update(header);

    int len = m.tsigstart - header.length;
    if (log.isTraceEnabled()) {
      log.trace(hexdump.dump("TSIG-HMAC message after header", messageBytes, header.length, len));
    }
    hmac.update(messageBytes, header.length, len);

    byte[] tsigVariables = getTsigVariables(fullSignature, tsig);
    hmac.update(tsigVariables);

    byte[] signature = tsig.getSignature();
    int badsig = verifySignature(hmac, signature);
    if (badsig != Rcode.NOERROR) {
      return badsig;
    }

    // validate time after the signature, as per
    // https://www.rfc-editor.org/rfc/rfc8945.html#section-5.4
    int badtime = verifyTime(tsig);
    if (badtime != Rcode.NOERROR) {
      return badtime;
    }

    m.tsigState = Message.TSIG_VERIFIED;
    return Rcode.NOERROR;
  }

  private static byte[] getTsigVariables(boolean fullSignature, TSIGRecord tsig) {
    DNSOutput out = new DNSOutput();
    if (fullSignature) {
      tsig.getName().toWireCanonical(out);
      out.writeU16(tsig.dclass);
      out.writeU32(tsig.ttl);
      tsig.getAlgorithm().toWireCanonical(out);
    }
    writeTsigTimerVariables(tsig.getTimeSigned(), tsig.getFudge(), out);
    if (fullSignature) {
      out.writeU16(tsig.getError());
      if (tsig.getOther() != null) {
        out.writeU16(tsig.getOther().length);
        out.writeByteArray(tsig.getOther());
      } else {
        out.writeU16(0);
      }
    }

    byte[] tsigVariables = out.toByteArray();
    if (log.isTraceEnabled()) {
      log.trace(hexdump.dump("TSIG-HMAC variables", tsigVariables));
    }
    return tsigVariables;
  }

  private static int verifySignature(Mac hmac, byte[] signature) {
    int digestLength = hmac.getMacLength();

    // rfc4635#section-3.1, 4.:
    // "MAC size" field is less than the larger of 10 (octets) and half
    // the length of the hash function in use
    int minDigestLength = Math.max(10, digestLength / 2);
    if (signature.length > digestLength) {
      log.debug(
          "BADSIG: signature too long, expected: {}, actual: {}", digestLength, signature.length);
      return Rcode.BADSIG;
    } else if (signature.length < minDigestLength) {
      log.debug(
          "BADSIG: signature too short, expected: {} of {}, actual: {}",
          minDigestLength,
          digestLength,
          signature.length);
      return Rcode.BADSIG;
    } else {
      byte[] expectedSignature = hmac.doFinal();
      if (!verify(expectedSignature, signature)) {
        if (log.isDebugEnabled()) {
          log.debug(
              "BADSIG: signature verification failed, expected: {}, actual: {}",
              base64.toString(expectedSignature),
              base64.toString(signature));
        }
        return Rcode.BADSIG;
      }
    }
    return Rcode.NOERROR;
  }

  private int verifyTime(TSIGRecord tsig) {
    Instant now = clock.instant();
    Duration delta = Duration.between(now, tsig.getTimeSigned()).abs();
    if (delta.compareTo(tsig.getFudge()) > 0) {
      log.debug(
          "BADTIME failure, now {} +/- tsig {} > fudge {}",
          now,
          tsig.getTimeSigned(),
          tsig.getFudge());
      return Rcode.BADTIME;
    }
    return Rcode.NOERROR;
  }

  /**
   * Returns the maximum length of a TSIG record generated by this key.
   *
   * @see TSIGRecord
   */
  public int recordLength() {
    return name.length()
        + 10
        + alg.length()
        + 8 // time signed, fudge
        + 18 // 2 byte MAC length, 16 byte MAC
        + 4 // original id, error
        + 8; // 2 byte error length, 6 byte max error field.
  }

  private static void hmacAddSignature(Mac hmac, TSIGRecord tsig) {
    byte[] signatureSize = DNSOutput.toU16(tsig.getSignature().length);
    if (log.isTraceEnabled()) {
      log.trace(hexdump.dump("TSIG-HMAC signature size", signatureSize));
      log.trace(hexdump.dump("TSIG-HMAC signature", tsig.getSignature()));
    }

    hmac.update(signatureSize);
    hmac.update(tsig.getSignature());
  }

  private static void writeTsigTimerVariables(Instant instant, Duration fudge, DNSOutput out) {
    writeTsigTime(instant, out);
    out.writeU16((int) fudge.getSeconds());
  }

  private static void writeTsigTime(Instant instant, DNSOutput out) {
    long time = instant.getEpochSecond();
    int timeHigh = (int) (time >> 32);
    long timeLow = time & 0xFFFFFFFFL;
    out.writeU16(timeHigh);
    out.writeU32(timeLow);
  }

  /**
   * A utility class for generating signed message responses.
   *
   * @since 3.5.3
   */
  public static class StreamGenerator {
    private final TSIG key;
    private final Mac sharedHmac;
    private final int signEveryNthMessage;

    private int numGenerated;
    private TSIGRecord lastTsigRecord;

    /**
     * Creates an instance to sign multiple message for use in a stream.
     *
     * <p>This class creates a {@link TSIGRecord} on every message to conform with <a
     * href="https://www.rfc-editor.org/rfc/rfc8945.html#section-5.3.1">RFC 8945, 5.3.1</a>.
     *
     * @param key The TSIG key used to create the signature records.
     * @param queryTsig The initial TSIG records, e.g. from a query to a server.
     */
    public StreamGenerator(TSIG key, TSIGRecord queryTsig) {
      // The TSIG MUST be included on all DNS messages in the response.
      this(key, queryTsig, 1);
    }

    /**
     * This constructor is <b>only</b> for unit-testing {@link StreamVerifier} with responses where
     * not every message is signed.
     */
    StreamGenerator(TSIG key, TSIGRecord queryTsig, int signEveryNthMessage) {
      if (signEveryNthMessage < 1 || signEveryNthMessage > 100) {
        throw new IllegalArgumentException("signEveryNthMessage must be between 1 and 100");
      }

      this.key = key;
      this.lastTsigRecord = queryTsig;
      this.signEveryNthMessage = signEveryNthMessage;
      sharedHmac = this.key.initHmac();
    }

    /**
     * Generate TSIG a signature for use of the message in a stream.
     *
     * @param message The message to sign.
     */
    public void generate(Message message) {
      generate(message, true);
    }

    void generate(Message message, boolean isLastMessage) {
      boolean isNthMessage = numGenerated % signEveryNthMessage == 0;
      boolean isFirstMessage = numGenerated == 0;
      if (isFirstMessage || isNthMessage || isLastMessage) {
        TSIGRecord r =
            key.generate(
                message,
                message.toWire(),
                Rcode.NOERROR,
                isFirstMessage ? lastTsigRecord : null,
                isFirstMessage,
                sharedHmac);
        message.addRecord(r, Section.ADDITIONAL);
        message.tsigState = Message.TSIG_SIGNED;
        lastTsigRecord = r;
        hmacAddSignature(sharedHmac, r);
      } else {
        byte[] responseBytes = message.toWire(Message.MAXLENGTH);
        sharedHmac.update(responseBytes);
      }

      numGenerated++;
    }
  }

  /** A utility class for verifying multiple message responses. */
  public static class StreamVerifier {
    private final TSIG key;
    private final Mac sharedHmac;
    private final TSIGRecord queryTsig;

    private int nresponses;
    private int lastsigned;

    /** {@code null} or the detailed error when validation failed due to a {@link Rcode#FORMERR}. */
    @Getter private String errorMessage;

    /** Creates an object to verify a multiple message response */
    public StreamVerifier(TSIG tsig, TSIGRecord queryTsig) {
      key = tsig;
      sharedHmac = key.initHmac();
      nresponses = 0;
      this.queryTsig = queryTsig;
    }

    /**
     * Verifies a TSIG record on an incoming message that is part of a multiple message response.
     * TSIG records must be present on the first and last messages, and at least every 100 records
     * in between. After calling this routine,{@link Message#isVerified()} may be called on this
     * message.
     *
     * <p>This overload assumes that the verified message is not the last one, which is required to
     * have a {@link TSIGRecord}. Use {@link #verify(Message, byte[], boolean)} to explicitly
     * specify the last message or check that the message is verified with {@link
     * Message#isVerified()}.
     *
     * @param message The message
     * @param messageBytes The message in unparsed form
     * @return The result of the verification (as an Rcode)
     * @see Rcode
     */
    public int verify(Message message, byte[] messageBytes) {
      return verify(message, messageBytes, false);
    }

    /**
     * Verifies a TSIG record on an incoming message that is part of a multiple message response.
     * TSIG records must be present on the first and last messages, and at least every 100 records
     * in between. After calling this routine, {@link Message#isVerified()} may be called on this
     * message.
     *
     * @param message The message
     * @param messageBytes The message in unparsed form
     * @param isLastMessage If true, verifies that the {@link Message} has an {@link TSIGRecord}.
     * @return The result of the verification (as an Rcode)
     * @see Rcode
     * @since 3.5.3
     */
    public int verify(Message message, byte[] messageBytes, boolean isLastMessage) {
      final String warningPrefix = "FORMERR: {}";
      TSIGRecord tsig = message.getTSIG();

      // https://datatracker.ietf.org/doc/html/rfc8945#section-5.3.1
      // [...] a client that receives DNS messages and verifies TSIG MUST accept up to 99
      // intermediary messages without a TSIG and MUST verify that both the first and last message
      // contain a TSIG.
      nresponses++;
      if (nresponses == 1) {
        if (tsig != null) {
          int result = key.verify(message, messageBytes, queryTsig, true, sharedHmac);
          hmacAddSignature(sharedHmac, tsig);
          lastsigned = nresponses;
          return result;
        } else {
          errorMessage = "missing required signature on first message";
          log.debug(warningPrefix, errorMessage);
          message.tsigState = Message.TSIG_FAILED;
          return Rcode.FORMERR;
        }
      }

      if (tsig != null) {
        int result = key.verify(message, messageBytes, null, false, sharedHmac);
        lastsigned = nresponses;
        hmacAddSignature(sharedHmac, tsig);
        return result;
      } else {
        boolean required = nresponses - lastsigned >= 100;
        if (required) {
          errorMessage = "Missing required signature on message #" + nresponses;
          log.debug(warningPrefix, errorMessage);
          message.tsigState = Message.TSIG_FAILED;
          return Rcode.FORMERR;
        } else if (isLastMessage) {
          errorMessage = "Missing required signature on last message";
          log.debug(warningPrefix, errorMessage);
          message.tsigState = Message.TSIG_FAILED;
          return Rcode.FORMERR;
        } else {
          errorMessage = "Intermediate message #" + nresponses + " without signature";
          log.debug(warningPrefix, errorMessage);
          addUnsignedMessageToMac(message, messageBytes, sharedHmac);
          return Rcode.NOERROR;
        }
      }
    }

    private void addUnsignedMessageToMac(Message m, byte[] messageBytes, Mac hmac) {
      byte[] header = m.getHeader().toWire();
      if (log.isTraceEnabled()) {
        log.trace(hexdump.dump("TSIG-HMAC header", header));
      }

      hmac.update(header);
      int len = messageBytes.length - header.length;
      if (log.isTraceEnabled()) {
        log.trace(hexdump.dump("TSIG-HMAC message after header", messageBytes, header.length, len));
      }

      hmac.update(messageBytes, header.length, len);
      m.tsigState = Message.TSIG_INTERMEDIATE;
    }
  }
}
