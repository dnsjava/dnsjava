// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.net.*;
import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * (old) IPv6 Address Record - maps a domain name to an IPv6 address
 *
 * @author Brian Wellington
 */

public class AAAARecord extends Record {

private short prefixBits;
private Inet6Address address;
private Name prefix;

private
AAAARecord() {}

/**
 * Creates an AAAA Record from the given data
 * @param address The address suffix
 */
public
AAAARecord(Name _name, short _dclass, int _ttl, int _prefixBits,
	 Inet6Address _address, Name _prefix)
throws IOException
{
	super(_name, Type.AAAA, _dclass, _ttl);
	address = _address;
}

AAAARecord(Name _name, short _dclass, int _ttl, int length,
	 DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.AAAA, _dclass, _ttl);

	if (in == null)
		return;

	byte [] data = new byte[16];
	in.read(data);
	address = new Inet6Address(data);
}

AAAARecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	   Name origin)
throws IOException
{
	super(_name, Type.AAAA, _dclass, _ttl);
	address = new Inet6Address(st.nextToken());
}

/** Converts to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (address == null)
		return;
	byte [] data = address.toBytes();
}

}
