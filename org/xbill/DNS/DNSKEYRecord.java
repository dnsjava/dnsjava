// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Key - contains a cryptographic public key for use by DNS.
 * The data can be converted to objects implementing
 * java.security.interfaces.PublicKey
 * @see DNSSEC
 *
 * @author Brian Wellington
 */

public class DNSKEYRecord extends KEYBase {

private static DNSKEYRecord member = new DNSKEYRecord();

public static class Protocol {
	private Protocol() {}

	/** Key will be used for DNSSEC */
	public static final int DNSSEC = 3;
}

public static class Flags {
	private Flags() {}

	/** Key is a zone key */
	public static final int ZONE_KEY = 0x100;

	/** Key is a secure entry point key */
	public static final int SEP_KEY = 0x1;
}

private
DNSKEYRecord() {}

private
DNSKEYRecord(Name name, int dclass, long ttl) {
	super(name, Type.KEY, dclass, ttl);
}

static DNSKEYRecord
getMember() {
	return member;
}

/**
 * Creates a KEY Record from the given data
 * @param flags Flags describing the key's properties
 * @param proto The protocol that the key was created for
 * @param alg The key's algorithm
 * @param key Binary data representing the key
 */
public
DNSKEYRecord(Name name, int dclass, long ttl, int flags, int proto, int alg,
	     byte [] key)
{
	super(name, Type.KEY, dclass, ttl, flags, proto, alg, key);
}

Record
rrFromWire(Name name, int type, int dclass, long ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	return rrFromWire(new DNSKEYRecord(name, dclass, ttl), length, in);
}

Record
rdataFromString(Name name, int dclass, long ttl, Tokenizer st, Name origin)
throws IOException
{
	return rdataFromString(new DNSKEYRecord(name, dclass, ttl), st, origin);
}

}
