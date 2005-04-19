// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;

/**
 * Key - contains a cryptographic public key for use by DNS.
 * The data can be converted to objects implementing
 * java.security.interfaces.PublicKey
 * @see DNSSEC
 *
 * @author Brian Wellington
 */

public class DNSKEYRecord extends KEYBase {

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

DNSKEYRecord() {}

Record
getObject() {
	return new DNSKEYRecord();
}

/**
 * Creates a DNSKEY Record from the given data
 * @param flags Flags describing the key's properties
 * @param proto The protocol that the key was created for
 * @param alg The key's algorithm
 * @param key Binary data representing the key
 */
public
DNSKEYRecord(Name name, int dclass, long ttl, int flags, int proto, int alg,
	     byte [] key)
{
	super(name, Type.DNSKEY, dclass, ttl, flags, proto, alg, key);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	flags = st.getUInt16();
	proto = st.getUInt8();
	String algString = st.getString();
	alg = DNSSEC.Algorithm.value(algString);
	if (alg < 0)
		throw st.exception("Invalid algorithm: " + algString);
	key = st.getBase64();
}

}
