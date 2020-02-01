// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * S/MIME cert association
 *
 * @see <a href="https://tools.ietf.org/html/rfc8162">RFC 8162: Using Secure DNS to Associate
 *     Certificates with Domain Names for S/MIME</a>
 * @author Brian Wellington
 */
public class SMIMEARecord extends TLSARecord {
  SMIMEARecord() {}

  /**
   * Creates an SMIMEA Record from the given data
   *
   * @param certificateUsage The provided association that will be used to match the certificate
   *     presented in the S/MIME handshake.
   * @param selector The part of the S/MIME certificate presented by the server that will be matched
   *     against the association data.
   * @param matchingType How the certificate association is presented.
   * @param certificateAssociationData The "certificate association data" to be matched.
   */
  public SMIMEARecord(
      Name name,
      int dclass,
      long ttl,
      int certificateUsage,
      int selector,
      int matchingType,
      byte[] certificateAssociationData) {
    super(
        name,
        Type.SMIMEA,
        dclass,
        ttl,
        certificateUsage,
        selector,
        matchingType,
        certificateAssociationData);
  }
}
