// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * IPv6 Address Record - maps a domain name to an IPv6 address
 *
 * @author Brian Wellington
 */

public class AAAARecord extends Record {

private Inet6Address address;

AAAARecord() {}

Record
getObject() {
	return new AAAARecord();
}

/**
 * Creates an AAAA Record from the given data
 * @param address The address suffix
 */
public
AAAARecord(Name name, int dclass, long ttl, Inet6Address address) {
	super(name, Type.AAAA, dclass, ttl);
	this.address = address;
}

void
rrFromWire(DNSInput in) throws IOException {
	if (in == null)
		return;

	address = new Inet6Address(in.readByteArray(16));
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	try {
		address = new Inet6Address(st.getString());
	}
	catch (TextParseException e) {
		throw st.exception(e.getMessage());
	}
}

/** Converts rdata to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (address != null)
		sb.append(address);
	return sb.toString();
}

/** Returns the address */
public Inet6Address
getAddress() {
	return address;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (address == null)
		return;
	byte [] b = address.toBytes();
	out.writeArray(b);
}

}
