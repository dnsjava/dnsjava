// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import lombok.Getter;

/**
 * EDNS option to provide additional information about the cause of DNS errors (RFC 8914).
 *
 * @since 3.4
 */
public class ExtendedErrorCodeOption extends EDNSOption {

  /** The error in question falls into a category that does not match known extended error codes. */
  public static final int OTHER = 0;

  /**
   * The resolver attempted to perform DNSSEC validation, but a {@link DNSKEYRecord} {@link RRset}
   * contained only unsupported DNSSEC algorithms.
   */
  public static final int UNSUPPORTED_DNSKEY_ALGORITHM = 1;

  /**
   * The resolver attempted to perform DNSSEC validation, but a {@link DSRecord} {@link RRset}
   * contained only unsupported Digest Types.
   */
  public static final int UNSUPPORTED_DS_DIGEST_TYPE = 2;

  /**
   * The resolver was unable to resolve the answer within its time limits and decided to answer with
   * previously cached data instead of answering with an error.
   */
  public static final int STALE_ANSWER = 3;

  /**
   * For policy reasons (legal obligation or malware filtering, for instance), an answer was forged.
   */
  public static final int FORGED_ANSWER = 4;

  /**
   * The resolver attempted to perform DNSSEC validation, but validation ended in the Indeterminate
   * state.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc4035>RFC 4035</a>
   */
  public static final int DNSSEC_INDETERMINATE = 5;

  /**
   * The resolver attempted to perform DNSSEC validation, but validation ended in the Bogus state.
   */
  public static final int DNSSEC_BOGUS = 6;

  /**
   * The resolver attempted to perform DNSSEC validation, but no signatures are presently valid and
   * some (often all) are expired.
   */
  public static final int SIGNATURE_EXPIRED = 7;

  /**
   * The resolver attempted to perform DNSSEC validation, but no signatures are presently valid and
   * at least some are not yet valid.
   */
  public static final int SIGNATURE_NOT_YET_VALID = 8;

  /**
   * A {@link DSRecord} existed at a parent, but no supported matching {@link DNSKEYRecord} could be
   * found for the child.
   */
  public static final int DNSKEY_MISSING = 9;

  /**
   * The resolver attempted to perform DNSSEC validation, but no {@link RRSIGRecord}s could be found
   * for at least one {@link RRset} where {@link RRSIGRecord}s were expected.
   */
  public static final int RRSIGS_MISSING = 10;

  /**
   * The resolver attempted to perform DNSSEC validation, but no Zone Key Bit was set in a DNSKEY.
   */
  public static final int NO_ZONE_KEY_BIT_SET = 11;

  /**
   * The resolver attempted to perform DNSSEC validation, but the requested data was missing and a
   * covering {@link NSECRecord} or {@link NSEC3Record} was not provided
   */
  public static final int NSEC_MISSING = 12;

  /** The resolver is returning the {@link Rcode#SERVFAIL} from its cache. */
  public static final int CACHED_ERROR = 13;

  /**
   * The server is unable to answer the query, as it was not fully functional when the query was
   * received.
   */
  public static final int NOT_READY = 14;

  /**
   * The server is unable to respond to the request because the domain is on a blocklist due to an
   * internal security policy imposed by the operator of the server resolving or forwarding the
   * query.
   */
  public static final int BLOCKED = 15;

  /**
   * The server is unable to respond to the request because the domain is on a blocklist due to an
   * external requirement imposed by an entity other than the operator of the server resolving or
   * forwarding the query.
   */
  public static final int CENSORED = 16;

  /**
   * The server is unable to respond to the request because the domain is on a blocklist as
   * requested by the client.
   */
  public static final int FILTERED = 17;

  /**
   * An authoritative server or recursive resolver that receives a query from an "unauthorized"
   * client can annotate its {@link Rcode#REFUSED} message with this code.
   */
  public static final int PROHIBITED = 18;

  /**
   * The resolver was unable to resolve an answer within its configured time limits and decided to
   * answer with a previously cached {@link Rcode#NXDOMAIN} answer instead of answering with an
   * error.
   */
  public static final int STALE_NXDOMAIN_ANSWER = 19;

  /**
   * Response to a query with the Recursion Desired (RD) bit clear, or when the server is not
   * configured for recursion (and the query is for a domain for which it is not authoritative).
   */
  public static final int NOT_AUTHORITATIVE = 20;

  /** The requested operation or query is not supported. */
  public static final int NOT_SUPPORTED = 21;

  /**
   * The resolver could not reach any of the authoritative name servers (or they potentially refused
   * to reply).
   */
  public static final int NO_REACHABLE_AUTHORITY = 22;

  /** An unrecoverable error occurred while communicating with another server. */
  public static final int NETWORK_ERROR = 23;

  /**
   * The authoritative server cannot answer with data for a zone it is otherwise configured to
   * support.
   */
  public static final int INVALID_DATA = 24;

  /**
   * The signature expired before it started to become valid.
   *
   * @since 3.6
   * @see <a href="https://github.com/NLnetLabs/unbound/pull/604#discussion_r802678343">Unbound
   *     PR#604</a>
   */
  public static final int SIGNATURE_EXPIRED_BEFORE_VALID = 25;

  /**
   * DNS over QUIC session resumption error.
   *
   * @since 3.6
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc9250#section-4.5-3">RFC 9250, 4.5</a>
   */
  public static final int TOO_EARLY = 26;

  /**
   * The NSEC3 iterations value is not supported.
   *
   * @since 3.6
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc9276#section-3.2">RFC 9276, 3.2</a>
   */
  public static final int UNSUPPORTED_NSEC3_ITERATIONS_VALUE = 27;

  /**
   * Unable to conform to policy.
   *
   * @since 3.6
   * @see <a
   *     href="https://datatracker.ietf.org/doc/draft-homburg-dnsop-codcp/01/">draft-homburg-dnsop-codcp-01</a>
   */
  public static final int UNABLE_TO_CONFORM_TO_POLICY = 28;

  /**
   * Result synthesized from aggressive NSEC cache.
   *
   * @since 3.6
   * @see <a href="https://github.com/PowerDNS/pdns/pull/12334">PowerDNS PR#12334</a>
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8198">RFC 8198</a>
   */
  public static final int SYNTHESIZED = 29;

  @Getter private int errorCode;
  @Getter private String text;

  private static final Mnemonic codes =
      new Mnemonic("EDNS Extended Error Codes", Mnemonic.CASE_SENSITIVE);

  static {
    codes.setMaximum(0xFFFF);
    codes.setPrefix("EDE");
    codes.add(OTHER, "OTHER");
    codes.add(UNSUPPORTED_DNSKEY_ALGORITHM, "UNSUPPORTED_DNSKEY_ALGORITHM");
    codes.add(UNSUPPORTED_DS_DIGEST_TYPE, "UNSUPPORTED_DS_DIGEST_TYPE");
    codes.add(STALE_ANSWER, "STALE_ANSWER");
    codes.add(FORGED_ANSWER, "FORGED_ANSWER");
    codes.add(DNSSEC_INDETERMINATE, "DNSSEC_INDETERMINATE");
    codes.add(DNSSEC_BOGUS, "DNSSEC_BOGUS");
    codes.add(SIGNATURE_EXPIRED, "SIGNATURE_EXPIRED");
    codes.add(SIGNATURE_NOT_YET_VALID, "SIGNATURE_NOT_YET_VALID");
    codes.add(DNSKEY_MISSING, "DNSKEY_MISSING");
    codes.add(RRSIGS_MISSING, "RRSIGS_MISSING");
    codes.add(NO_ZONE_KEY_BIT_SET, "NO_ZONE_KEY_BIT_SET");
    codes.add(NSEC_MISSING, "NSEC_MISSING");
    codes.add(CACHED_ERROR, "CACHED_ERROR");
    codes.add(NOT_READY, "NOT_READY");
    codes.add(BLOCKED, "BLOCKED");
    codes.add(CENSORED, "CENSORED");
    codes.add(FILTERED, "FILTERED");
    codes.add(PROHIBITED, "PROHIBITED");
    codes.add(STALE_NXDOMAIN_ANSWER, "STALE_NXDOMAIN_ANSWER");
    codes.add(NOT_AUTHORITATIVE, "NOT_AUTHORITATIVE");
    codes.add(NOT_SUPPORTED, "NOT_SUPPORTED");
    codes.add(NO_REACHABLE_AUTHORITY, "NO_REACHABLE_AUTHORITY");
    codes.add(NETWORK_ERROR, "NETWORK_ERROR");
    codes.add(INVALID_DATA, "INVALID_DATA");
    codes.add(SIGNATURE_EXPIRED_BEFORE_VALID, "SIGNATURE_EXPIRED_BEFORE_VALID");
    codes.add(TOO_EARLY, "TOO_EARLY");
    codes.add(UNSUPPORTED_NSEC3_ITERATIONS_VALUE, "UNSUPPORTED_NSEC3_ITERATIONS_VALUE");
    codes.add(UNABLE_TO_CONFORM_TO_POLICY, "UNABLE_TO_CONFORM_TO_POLICY");
    codes.add(SYNTHESIZED, "SYNTHESIZED");
  }

  /**
   * Gets the text mnemonic corresponding to an EDE value.
   *
   * @since 3.5
   */
  public static String text(int code) {
    return codes.getText(code);
  }

  /**
   * Gets the numeric value corresponding to an EDE text mnemonic.
   *
   * @since 3.5
   */
  public static int code(String text) {
    return codes.getValue(text);
  }

  /** Creates an extended error code EDNS option. */
  ExtendedErrorCodeOption() {
    super(Code.EDNS_EXTENDED_ERROR);
  }

  /**
   * Creates an extended error code EDNS option.
   *
   * @param errorCode the extended error.
   * @param text optional error message intended for human readers.
   */
  public ExtendedErrorCodeOption(int errorCode, String text) {
    super(Code.EDNS_EXTENDED_ERROR);
    this.errorCode = errorCode;
    this.text = text;
  }

  /**
   * Creates an extended error code EDNS option.
   *
   * @param errorCode the extended error.
   */
  public ExtendedErrorCodeOption(int errorCode) {
    this(errorCode, null);
  }

  @Override
  void optionFromWire(DNSInput in) throws IOException {
    errorCode = in.readU16();
    if (in.remaining() > 0) {
      byte[] data = in.readByteArray();
      int len = data.length;

      // EDE text may be null terminated but MUST NOT be assumed to be
      if (data[data.length - 1] == 0) {
        len--;
      }

      text = new String(data, 0, len, StandardCharsets.UTF_8);
    }
  }

  @Override
  void optionToWire(DNSOutput out) {
    out.writeU16(errorCode);
    if (text != null && !text.isEmpty()) {
      out.writeByteArray(text.getBytes(StandardCharsets.UTF_8));
    }
  }

  @Override
  String optionToString() {
    if (text == null) {
      return codes.getText(errorCode);
    }
    return codes.getText(errorCode) + ": " + text;
  }
}
