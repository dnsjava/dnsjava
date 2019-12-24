// Copyright (c) 2001-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import org.xbill.DNS.DNSSEC.DNSSECException;

/**
 * Creates SIG(0) transaction signatures.
 *
 * @author Pasi Eronen
 * @author Brian Wellington
 */
public class SIG0 {

  /**
   * The default validity period for outgoing SIG(0) signed messages. Can be overriden by the
   * sig0validity option.
   */
  private static final Duration VALIDITY = Duration.ofSeconds(300);

  private SIG0() {}

  /**
   * Sign a message with SIG(0). The DNS key and private key must refer to the same underlying
   * cryptographic key.
   *
   * @param message The message to be signed
   * @param key The DNSKEY record to use as part of signing
   * @param privkey The PrivateKey to use when signing
   * @param previous If this message is a response, the SIG(0) from the query
   */
  public static void signMessage(
      Message message, KEYRecord key, PrivateKey privkey, SIGRecord previous)
      throws DNSSEC.DNSSECException {
    signMessage(message, key, privkey, previous, Instant.now());
  }

  /**
   * Sign a message with SIG(0). The DNS key and private key must refer to the same underlying
   * cryptographic key.
   *
   * @param message The message to be signed
   * @param key The DNSKEY record to use as part of signing
   * @param privkey The PrivateKey to use when signing
   * @param previous If this message is a response, the SIG(0) from the query
   * @param timeSigned The time instant when the message has been signed.
   */
  public static void signMessage(
      Message message, KEYRecord key, PrivateKey privkey, SIGRecord previous, Instant timeSigned)
      throws DNSSEC.DNSSECException {

    int validityOption = Options.intValue("sig0validity");
    Duration validity;
    if (validityOption < 0) {
      validity = VALIDITY;
    } else {
      validity = Duration.ofSeconds(validityOption);
    }

    Instant timeExpires = timeSigned.plus(validity);

    SIGRecord sig = DNSSEC.signMessage(message, previous, key, privkey, timeSigned, timeExpires);

    message.addRecord(sig, Section.ADDITIONAL);
  }

  /**
   * Verify a message using SIG(0). Uses the current system clock for the date/time.
   *
   * @param message The message to be signed
   * @param b An array containing the message in unparsed form. This is necessary since SIG(0) signs
   *     the message in wire format, and we can't recreate the exact wire format (with the same name
   *     compression).
   * @param key The KEY record to verify the signature with.
   * @param previous If this message is a response, the SIG(0) from the query
   */
  public static void verifyMessage(Message message, byte[] b, KEYRecord key, SIGRecord previous)
      throws DNSSECException {
    verifyMessage(message, b, key, previous, Instant.now());
  }

  /**
   * Verify a message using SIG(0).
   *
   * @param message The message to be signed
   * @param b An array containing the message in unparsed form. This is necessary since SIG(0) signs
   *     the message in wire format, and we can't recreate the exact wire format (with the same name
   *     compression).
   * @param key The KEY record to verify the signature with.
   * @param previous If this message is a response, the SIG(0) from the query
   * @param now the time instant to verify the message.
   */
  public static void verifyMessage(
      Message message, byte[] b, KEYRecord key, SIGRecord previous, Instant now)
      throws DNSSEC.DNSSECException {
    SIGRecord sig = null;
    for (Record record : message.getSection(Section.ADDITIONAL)) {
      if (record.getType() != Type.SIG) {
        continue;
      }
      if (((SIGRecord) record).getTypeCovered() != 0) {
        continue;
      }
      sig = (SIGRecord) record;
      break;
    }
    DNSSEC.verifyMessage(message, b, sig, previous, key, now);
  }
}
