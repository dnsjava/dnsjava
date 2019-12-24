// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.utils.base64;

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

  /** The domain name representing the HMAC-MD5 algorithm (deprecated). */
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

  private static Map<Name, String> algMap;

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

  public static Name algorithmToName(String alg) {
    for (Map.Entry<Name, String> entry : algMap.entrySet()) {
      if (alg.equalsIgnoreCase(entry.getValue())) {
        return entry.getKey();
      }
    }
    throw new IllegalArgumentException("Unknown algorithm");
  }

  public static String nameToAlgorithm(Name name) {
    String alg = algMap.get(name);
    if (alg != null) {
      return alg;
    }
    throw new IllegalArgumentException("Unknown algorithm");
  }

  /** The default fudge value for outgoing packets. Can be overriden by the tsigfudge option. */
  public static final Duration FUDGE = Duration.ofSeconds(300);

  private Name name, alg;
  private Mac hmac;

  /**
   * Verifies the data (computes the secure hash and compares it to the input)
   *
   * @param mac The HMAC generator
   * @param signature The signature to compare against
   * @return true if the signature matches, false otherwise
   */
  private static boolean verify(Mac mac, byte[] signature) {
    return verify(mac, signature, false);
  }

  /**
   * Verifies the data (computes the secure hash and compares it to the input)
   *
   * @param mac The HMAC generator
   * @param signature The signature to compare against
   * @param truncation_ok If true, the signature may be truncated; only the number of bytes in the
   *     provided signature are compared.
   * @return true if the signature matches, false otherwise
   */
  private static boolean verify(Mac mac, byte[] signature, boolean truncation_ok) {
    byte[] expected = mac.doFinal();
    if (truncation_ok && signature.length < expected.length) {
      byte[] truncated = new byte[signature.length];
      System.arraycopy(expected, 0, truncated, 0, truncated.length);
      expected = truncated;
    }
    return Arrays.equals(signature, expected);
  }

  private void init_hmac(String macAlgorithm, SecretKey key) {
    try {
      hmac = Mac.getInstance(macAlgorithm);
      hmac.init(key);
    } catch (GeneralSecurityException ex) {
      throw new IllegalArgumentException("Caught security exception setting up HMAC.");
    }
  }

  /**
   * Creates a new TSIG key, which can be used to sign or verify a message.
   *
   * @param algorithm The algorithm of the shared key.
   * @param name The name of the shared key.
   * @param keyBytes The shared key's data.
   */
  public TSIG(Name algorithm, Name name, byte[] keyBytes) {
    this.name = name;
    this.alg = algorithm;
    String macAlgorithm = nameToAlgorithm(algorithm);
    SecretKey key = new SecretKeySpec(keyBytes, macAlgorithm);
    init_hmac(macAlgorithm, key);
  }

  /**
   * Creates a new TSIG key, which can be used to sign or verify a message.
   *
   * @param algorithm The algorithm of the shared key.
   * @param name The name of the shared key.
   * @param key The shared key.
   */
  public TSIG(Name algorithm, Name name, SecretKey key) {
    this.name = name;
    this.alg = algorithm;
    String macAlgorithm = nameToAlgorithm(algorithm);
    init_hmac(macAlgorithm, key);
  }

  /**
   * Creates a new TSIG key from a pre-initialized Mac instance. This assumes that init() has
   * already been called on the mac to set up the key.
   *
   * @param mac The JCE HMAC object
   * @param name The name of the key
   */
  public TSIG(Mac mac, Name name) {
    this.name = name;
    this.hmac = mac;
    this.alg = algorithmToName(mac.getAlgorithm());
  }

  /**
   * Creates a new TSIG key with the hmac-md5 algorithm, which can be used to sign or verify a
   * message.
   *
   * @param name The name of the shared key.
   * @param key The shared key's data.
   */
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
    String macAlgorithm = nameToAlgorithm(this.alg);
    init_hmac(macAlgorithm, new SecretKeySpec(keyBytes, macAlgorithm));
  }

  /**
   * Creates a new TSIG object, which can be used to sign or verify a message.
   *
   * @param name The name of the shared key.
   * @param algorithm The algorithm of the shared key. The legal values are "hmac-md5", "hmac-sha1",
   *     "hmac-sha224", "hmac-sha256", "hmac-sha384", and "hmac-sha512".
   * @param key The shared key's data represented as a base64 encoded string.
   * @throws IllegalArgumentException The key name is an invalid name
   * @throws IllegalArgumentException The key data is improperly encoded
   */
  public TSIG(String algorithm, String name, String key) {
    this(algorithmToName(algorithm), name, key);
  }

  /**
   * Creates a new TSIG object with the hmac-md5 algorithm, which can be used to sign or verify a
   * message.
   *
   * @param name The name of the shared key
   * @param key The shared key's data, represented as a base64 encoded string.
   * @throws IllegalArgumentException The key name is an invalid name
   * @throws IllegalArgumentException The key data is improperly encoded
   */
  public TSIG(String name, String key) {
    this(HMAC_MD5, name, key);
  }

  /**
   * Creates a new TSIG object, which can be used to sign or verify a message.
   *
   * @param str The TSIG key, in the form name:secret, name/secret, alg:name:secret, or
   *     alg/name/secret. If an algorithm is specified, it must be "hmac-md5", "hmac-sha1", or
   *     "hmac-sha256".
   * @throws IllegalArgumentException The string does not contain both a name and secret.
   * @throws IllegalArgumentException The key name is an invalid name
   * @throws IllegalArgumentException The key data is improperly encoded
   */
  public static TSIG fromString(String str) {
    String[] parts = str.split("[:/]", 3);
    if (parts.length < 2) {
      throw new IllegalArgumentException("Invalid TSIG key specification");
    }
    if (parts.length == 3) {
      try {
        return new TSIG(parts[0], parts[1], parts[2]);
      } catch (IllegalArgumentException e) {
        parts = str.split("[:/]", 2);
      }
    }
    return new TSIG(HMAC_MD5, parts[0], parts[1]);
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
    Instant timeSigned;
    if (error != Rcode.BADTIME) {
      timeSigned = Instant.now();
    } else {
      timeSigned = old.getTimeSigned();
    }
    Duration fudge;
    boolean signing = false;
    if (error == Rcode.NOERROR || error == Rcode.BADTIME) {
      signing = true;
      hmac.reset();
    }

    int fudgeOption = Options.intValue("tsigfudge");
    if (fudgeOption < 0 || fudgeOption > 0x7FFF) {
      fudge = FUDGE;
    } else {
      fudge = Duration.ofSeconds(fudgeOption);
    }

    if (old != null) {
      DNSOutput out = new DNSOutput();
      out.writeU16(old.getSignature().length);
      if (signing) {
        hmac.update(out.toByteArray());
        hmac.update(old.getSignature());
      }
    }

    /* Digest the message */
    if (signing) {
      hmac.update(b);
    }

    DNSOutput out = new DNSOutput();
    name.toWireCanonical(out);
    out.writeU16(DClass.ANY); /* class */
    out.writeU32(0); /* ttl */
    alg.toWireCanonical(out);
    long time = timeSigned.getEpochSecond();
    int timeHigh = (int) (time >> 32);
    long timeLow = (time & 0xFFFFFFFFL);
    out.writeU16(timeHigh);
    out.writeU32(timeLow);
    out.writeU16((int) fudge.getSeconds());

    out.writeU16(error);
    out.writeU16(0); /* No other data */

    if (signing) {
      hmac.update(out.toByteArray());
    }

    byte[] signature;
    if (signing) {
      signature = hmac.doFinal();
    } else {
      signature = new byte[0];
    }

    byte[] other = null;
    if (error == Rcode.BADTIME) {
      out = new DNSOutput();
      time = Instant.now().getEpochSecond();
      timeHigh = (int) (time >> 32);
      timeLow = (time & 0xFFFFFFFFL);
      out.writeU16(timeHigh);
      out.writeU32(timeLow);
      other = out.toByteArray();
    }

    return (new TSIGRecord(
        name,
        DClass.ANY,
        0,
        alg,
        timeSigned,
        fudge,
        signature,
        m.getHeader().getID(),
        error,
        other));
  }

  /**
   * Generates a TSIG record with a specific error for a message and adds it to the message.
   *
   * @param m The message
   * @param error The error
   * @param old If this message is a response, the TSIG from the request
   */
  public void apply(Message m, int error, TSIGRecord old) {
    Record r = generate(m, m.toWire(), error, old);
    m.addRecord(r, Section.ADDITIONAL);
    m.tsigState = Message.TSIG_SIGNED;
  }

  /**
   * Generates a TSIG record for a message and adds it to the message
   *
   * @param m The message
   * @param old If this message is a response, the TSIG from the request
   */
  public void apply(Message m, TSIGRecord old) {
    apply(m, Rcode.NOERROR, old);
  }

  /**
   * Generates a TSIG record for a message and adds it to the message
   *
   * @param m The message
   * @param old If this message is a response, the TSIG from the request
   */
  public void applyStream(Message m, TSIGRecord old, boolean first) {
    if (first) {
      apply(m, old);
      return;
    }
    Instant timeSigned = Instant.now();
    Duration fudge;
    hmac.reset();

    int fudgeOption = Options.intValue("tsigfudge");
    if (fudgeOption < 0 || fudgeOption > 0x7FFF) {
      fudge = FUDGE;
    } else {
      fudge = Duration.ofSeconds(fudgeOption);
    }

    DNSOutput out = new DNSOutput();
    out.writeU16(old.getSignature().length);
    hmac.update(out.toByteArray());
    hmac.update(old.getSignature());

    /* Digest the message */
    hmac.update(m.toWire());

    out = new DNSOutput();
    long time = timeSigned.getEpochSecond();
    int timeHigh = (int) (time >> 32);
    long timeLow = (time & 0xFFFFFFFFL);
    out.writeU16(timeHigh);
    out.writeU32(timeLow);
    out.writeU16((int) fudge.getSeconds());

    hmac.update(out.toByteArray());

    byte[] signature = hmac.doFinal();
    Record r =
        new TSIGRecord(
            name,
            DClass.ANY,
            0,
            alg,
            timeSigned,
            fudge,
            signature,
            m.getHeader().getID(),
            Rcode.NOERROR,
            null);
    m.addRecord(r, Section.ADDITIONAL);
    m.tsigState = Message.TSIG_SIGNED;
  }

  /**
   * Verifies a TSIG record on an incoming message. Since this is only called in the context where a
   * TSIG is expected to be present, it is an error if one is not present. After calling this
   * routine, Message.isVerified() may be called on this message.
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
   * @param m The message to verify
   * @param b An array containing the message in unparsed form. This is necessary since TSIG signs
   *     the message in wire format, and we can't recreate the exact wire format (with the same name
   *     compression).
   * @param old If this message is a response, the TSIG from the request
   * @return The result of the verification (as an Rcode)
   * @see Rcode
   */
  public int verify(Message m, byte[] b, TSIGRecord old) {
    m.tsigState = Message.TSIG_FAILED;
    TSIGRecord tsig = m.getTSIG();
    hmac.reset();
    if (tsig == null) {
      return Rcode.FORMERR;
    }

    if (!tsig.getName().equals(name) || !tsig.getAlgorithm().equals(alg)) {
      log.debug("BADKEY failure");
      return Rcode.BADKEY;
    }
    Duration delta = Duration.between(Instant.now(), tsig.getTimeSigned()).abs();
    if (delta.compareTo(tsig.getFudge()) > 0) {
      log.debug("BADTIME failure");
      return Rcode.BADTIME;
    }

    if (old != null && tsig.getError() != Rcode.BADKEY && tsig.getError() != Rcode.BADSIG) {
      DNSOutput out = new DNSOutput();
      out.writeU16(old.getSignature().length);
      hmac.update(out.toByteArray());
      hmac.update(old.getSignature());
    }
    m.getHeader().decCount(Section.ADDITIONAL);
    byte[] header = m.getHeader().toWire();
    m.getHeader().incCount(Section.ADDITIONAL);
    hmac.update(header);

    int len = m.tsigstart - header.length;
    hmac.update(b, header.length, len);

    DNSOutput out = new DNSOutput();
    tsig.getName().toWireCanonical(out);
    out.writeU16(tsig.dclass);
    out.writeU32(tsig.ttl);
    tsig.getAlgorithm().toWireCanonical(out);
    long time = tsig.getTimeSigned().getEpochSecond();
    int timeHigh = (int) (time >> 32);
    long timeLow = (time & 0xFFFFFFFFL);
    out.writeU16(timeHigh);
    out.writeU32(timeLow);
    out.writeU16((int) tsig.getFudge().getSeconds());
    out.writeU16(tsig.getError());
    if (tsig.getOther() != null) {
      out.writeU16(tsig.getOther().length);
      out.writeByteArray(tsig.getOther());
    } else {
      out.writeU16(0);
    }

    hmac.update(out.toByteArray());

    byte[] signature = tsig.getSignature();
    int digestLength = hmac.getMacLength();
    int minDigestLength;
    if (hmac.getAlgorithm().toLowerCase().contains("md5")) {
      minDigestLength = 10;
    } else {
      minDigestLength = digestLength / 2;
    }

    if (signature.length > digestLength) {
      log.debug("BADSIG: signature too long");
      return Rcode.BADSIG;
    } else if (signature.length < minDigestLength) {
      log.debug("BADSIG: signature too short");
      return Rcode.BADSIG;
    } else if (!verify(hmac, signature, true)) {
      log.debug("BADSIG: signature verification");
      return Rcode.BADSIG;
    }

    m.tsigState = Message.TSIG_VERIFIED;
    return Rcode.NOERROR;
  }

  /**
   * Returns the maximum length of a TSIG record generated by this key.
   *
   * @see TSIGRecord
   */
  public int recordLength() {
    return (name.length()
        + 10
        + alg.length()
        + 8 // time signed, fudge
        + 18 // 2 byte MAC length, 16 byte MAC
        + 4 // original id, error
        + 8); // 2 byte error length, 6 byte max error field.
  }

  public static class StreamVerifier {
    /** A helper class for verifying multiple message responses. */
    private TSIG key;

    private Mac verifier;
    private int nresponses;
    private int lastsigned;
    private TSIGRecord lastTSIG;

    /** Creates an object to verify a multiple message response */
    public StreamVerifier(TSIG tsig, TSIGRecord old) {
      key = tsig;
      verifier = tsig.hmac;
      nresponses = 0;
      lastTSIG = old;
    }

    /**
     * Verifies a TSIG record on an incoming message that is part of a multiple message response.
     * TSIG records must be present on the first and last messages, and at least every 100 records
     * in between. After calling this routine, Message.isVerified() may be called on this message.
     *
     * @param m The message
     * @param b The message in unparsed form
     * @return The result of the verification (as an Rcode)
     * @see Rcode
     */
    public int verify(Message m, byte[] b) {
      TSIGRecord tsig = m.getTSIG();

      nresponses++;

      if (nresponses == 1) {
        int result = key.verify(m, b, lastTSIG);
        if (result == Rcode.NOERROR) {
          byte[] signature = tsig.getSignature();
          DNSOutput out = new DNSOutput();
          out.writeU16(signature.length);
          verifier.update(out.toByteArray());
          verifier.update(signature);
        }
        lastTSIG = tsig;
        return result;
      }

      if (tsig != null) {
        m.getHeader().decCount(Section.ADDITIONAL);
      }
      byte[] header = m.getHeader().toWire();
      if (tsig != null) {
        m.getHeader().incCount(Section.ADDITIONAL);
      }
      verifier.update(header);

      int len;
      if (tsig == null) {
        len = b.length - header.length;
      } else {
        len = m.tsigstart - header.length;
      }
      verifier.update(b, header.length, len);

      if (tsig != null) {
        lastsigned = nresponses;
        lastTSIG = tsig;
      } else {
        boolean required = (nresponses - lastsigned >= 100);
        if (required) {
          m.tsigState = Message.TSIG_FAILED;
          return Rcode.FORMERR;
        } else {
          m.tsigState = Message.TSIG_INTERMEDIATE;
          return Rcode.NOERROR;
        }
      }

      if (!tsig.getName().equals(key.name) || !tsig.getAlgorithm().equals(key.alg)) {
        log.debug("BADKEY failure");
        m.tsigState = Message.TSIG_FAILED;
        return Rcode.BADKEY;
      }

      DNSOutput out = new DNSOutput();
      long time = tsig.getTimeSigned().getEpochSecond();
      int timeHigh = (int) (time >> 32);
      long timeLow = (time & 0xFFFFFFFFL);
      out.writeU16(timeHigh);
      out.writeU32(timeLow);
      out.writeU16((int) tsig.getFudge().getSeconds());
      verifier.update(out.toByteArray());

      if (!TSIG.verify(verifier, tsig.getSignature())) {
        log.debug("BADSIG failure");
        m.tsigState = Message.TSIG_FAILED;
        return Rcode.BADSIG;
      }

      verifier.reset();
      out = new DNSOutput();
      out.writeU16(tsig.getSignature().length);
      verifier.update(out.toByteArray());
      verifier.update(tsig.getSignature());

      m.tsigState = Message.TSIG_VERIFIED;
      return Rcode.NOERROR;
    }
  }
}
