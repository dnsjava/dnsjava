// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.net.*;
import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * IPv6 Address Record - maps a domain name to an IPv6 address
 *
 * @author Brian Wellington
 */

public class AAAARecord extends Record {

private static AAAARecord member = new AAAARecord();

private Inet6Address address;

private
AAAARecord() {}

private
AAAARecord(Name name, short dclass, int ttl) {
	super(name, Type.AAAA, dclass, ttl);
}

static AAAARecord
getMember() {
	return member;
}

/**
 * Creates an AAAA Record from the given data
 * @param address The address suffix
 */
public
AAAARecord(Name name, short dclass, int ttl, Inet6Address address) {
	this(name, dclass, ttl);
	this.address = address;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	AAAARecord rec = new AAAARecord(name, dclass, ttl);

	if (in == null)
		return rec;

	byte [] data = new byte[16];
	in.read(data);
	rec.address = new Inet6Address(data);
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	AAAARecord rec = new AAAARecord(name, dclass, ttl);
	rec.address = new Inet6Address(nextString(st));
	return rec;
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
