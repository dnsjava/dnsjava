// Copyright (c) 1999-2003 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * A6 Record - maps a domain name to an IPv6 address (experimental)
 *
 * @author Brian Wellington
 */

public class A6Record extends Record {

private static A6Record member = new A6Record();

private int prefixBits;
private Inet6Address suffix;
private Name prefix;

private
A6Record() {}

private
A6Record(Name name, int dclass, long ttl) {
	super(name, Type.A6, dclass, ttl);
}

static A6Record
getMember() {
	return member;
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
	this(name, dclass, ttl);
	checkU8("prefixBits", prefixBits);
	this.prefixBits = prefixBits;
	this.suffix = suffix;
	if (prefix != null && !prefix.isAbsolute())
		throw new RelativeNameException(prefix);
	this.prefix = prefix;
}

Record
rrFromWire(Name name, int type, int dclass, long ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	A6Record rec = new A6Record(name, dclass, ttl);

	if (in == null)
		return rec;

	rec.prefixBits = in.readUnsignedByte();
	int suffixbits = 128 - rec.prefixBits;
	int suffixbytes = (suffixbits + 7) / 8;
	byte [] data = new byte[suffixbytes];
	in.read(data);
	rec.suffix = new Inet6Address(128 - rec.prefixBits, data);
	if (rec.prefixBits > 0)
		rec.prefix = new Name(in);
	return rec;
}

Record
rdataFromString(Name name, int dclass, long ttl, Tokenizer st, Name origin)
throws IOException
{
	A6Record rec = new A6Record(name, dclass, ttl);
	rec.prefixBits = st.getUInt8();
	try {
		rec.suffix = new Inet6Address(st.getString());
	}
	catch (TextParseException e) {
		throw st.exception(e.getMessage());
	}
	if (rec.prefixBits > 0)
		rec.prefix = st.getName(origin);
	return rec;
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
