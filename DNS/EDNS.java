// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

/**
 * Extended DNS.  EDNS is a method to extend the DNS protocol while
 * providing backwards compatibility and not significantly chaning
 * the protocol.  This implementation of EDNS0 is partially complete.
 * @see OPTRecord
 */

public class EDNS {

/**
 * Creates a new OPT record
 * @param payloadSize The maximum UDP packet size that can be reassembled.
 */
public static OPTRecord
newOPT(int payloadSize) {
	return new OPTRecord(Name.root, (short)payloadSize, 0);
}

}
