// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.net.*;
import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * A6 Record - maps a domain name to an IPv6 address (experimental)
 *
 * @author Brian Wellington
 */

public class A6Record extends Record {

private static A6Record member = new A6Record();

private short prefixBits;
private Inet6Address suffix;
private Name prefix;

private
A6Record() {}

private
A6Record(Name name, short dclass, int ttl) {
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
A6Record(Name name, short dclass, int ttl, int prefixBits,
	 Inet6Address suffix, Name prefix)
{
	this(name, dclass, ttl);
	this.prefixBits = (short) prefixBits;
	this.suffix = suffix;
	this.prefix = prefix;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	A6Record rec = new A6Record(name, dclass, ttl);

	if (in == null)
		return rec;

	rec.prefixBits = in.readByte();
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
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	A6Record rec = new A6Record(name, dclass, ttl);
	rec.prefixBits = Short.parseShort(st.nextToken());
	rec.suffix = new Inet6Address(st.nextToken());
	if (rec.prefixBits > 0) {
		rec.prefix = Name.fromString(st.nextToken(), origin);
		rec.prefix.checkAbsolute("read an A6 record");
	}
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
public short
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
