// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * An interface to a DNSSEC Verifier.  This is used to verify the validity
 * of data received by dnsjava.  The specific implementation of the verifier
 * is expected to store trusted keys in some way.  The Verifier will use
 * these trusted keys as well as secure cached keys to verify data.
 * @see org.xbill.DNS.security.DNSSECVerifier
 *
 * @author Brian Wellington
 */

public interface Verifier {

/**
 * Verifies this RRset, using secure keys found in this Cache if necessary.
 * @see RRset
 * @see Cache
 */
int verify(RRset set, Cache cache);

}
