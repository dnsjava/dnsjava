// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.net.*;
import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Address Record - maps a domain name to an IPv6 address
 *
 * @author Brian Wellington
 */

public class A6Record extends Record {

private short prefixBits;
private Inet6Address suffix;
private Name prefix;

private
A6Record() {}

/**
 * Creates an A6 Record from the given data
 * @param prefixBits The number of bits in the address prefix
 * @param suffix The address suffix
 * @param prefix The name of the prefix
 */
public
A6Record(Name _name, short _dclass, int _ttl, int _prefixBits,
	 Inet6Address _suffix, Name _prefix)
throws IOException
{
	super(_name, Type.A6, _dclass, _ttl);
	prefixBits = (short) _prefixBits;
	suffix = _suffix;
	prefix = _prefix;
}

A6Record(Name _name, short _dclass, int _ttl, int length,
	 DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.A6, _dclass, _ttl);

	if (in == null)
		return;

	prefixBits = in.readByte();
	int suffixbits = 128 - prefixBits;
	int suffixbytes = (suffixbits + 7) / 8;
	byte [] data = new byte[suffixbytes];
	in.read(data);
	suffix = new Inet6Address(128 - prefixBits, data);
	if (prefixBits > 0)
		prefix = new Name(in, c);
}

A6Record(Name _name, short _dclass, int _ttl, MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, Type.A6, _dclass, _ttl);
	prefixBits = Short.parseShort(st.nextToken());
	suffix = new Inet6Address(st.nextToken());
	if (prefixBits > 0)
		prefix = new Name(st.nextToken(), origin);
}

/** Converts to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (suffix == null)
		return;
	out.write(prefixBits);
	int suffixbits = 128 - prefixBits;
	int suffixbytes = (suffixbits + 7) / 8;
	byte [] data = suffix.toBytes();
	out.write(data, 16 - suffixbytes, suffixbytes);
	if (prefix != null)
		prefix.toWire(out, null);
}

}
