// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * A6 Record - maps a domain name to an IPv6 address (experimental)
 *
 * @author Brian Wellington
 */

public class A6Record extends Record {

private int prefixBits;
private Inet6Address suffix;
private Name prefix;

A6Record() {}

Record
getObject() {
	return new A6Record();
}

/**
 * Creates an A6 Record from the given data
 * @param prefixBits The number of bits in the address prefix
 * @param suffix The address suffix
 * @param prefix The name of the prefix
 */
public
A6Record(Name name, int dclass, long ttl, int prefixBits,
	 Inet6Address suffix, Name prefix)
{
	super(name, Type.A6, dclass, ttl);
	checkU8("prefixBits", prefixBits);
	this.prefixBits = prefixBits;
	this.suffix = suffix;
	if (prefix != null && !prefix.isAbsolute())
		throw new RelativeNameException(prefix);
	this.prefix = prefix;
}

void
rrFromWire(DNSInput in) throws IOException {
	if (in == null)
		return;

	prefixBits = in.readU8();
	int suffixbits = 128 - prefixBits;
	int suffixbytes = (suffixbits + 7) / 8;
	suffix = new Inet6Address(128 - prefixBits,
				  in.readByteArray(suffixbytes));
	if (prefixBits > 0)
		prefix = new Name(in);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	prefixBits = st.getUInt8();
	try {
		suffix = new Inet6Address(st.getString());
	}
	catch (TextParseException e) {
		throw st.exception(e.getMessage());
	}
	if (prefixBits > 0)
		prefix = st.getName(origin);
}

/** Converts rdata to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (suffix != null) {
		sb.append(prefixBits);
		sb.append(" ");
		sb.append(suffix);
		if (prefix != null) {
			sb.append(" ");
			sb.append(prefix);
		}
	}
	return sb.toString();
}

/** Returns the number of bits in the prefix */
public int
getPrefixBits() {
	return prefixBits;
}

/** Returns the address suffix */
public Inet6Address
getSuffix() {
	return suffix;
}

/** Returns the address prefix */
public Name
getPrefix() {
	return prefix;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (suffix == null)
		return;
	out.write(prefixBits);
	int suffixbits = 128 - prefixBits;
	int suffixbytes = (suffixbits + 7) / 8;
	byte [] data = suffix.toBytes();
	out.write(data, 16 - suffixbytes, suffixbytes);
	if (prefix != null)
		prefix.toWire(out, null, canonical);
}

}
