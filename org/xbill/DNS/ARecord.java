// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.net.*;
import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Address Record - maps a domain name to an Internet address
 *
 * @author Brian Wellington
 */

public class ARecord extends Record {

private static ARecord member = new ARecord();

private byte [] addr;

private
ARecord() {}

private
ARecord(Name name, short dclass, int ttl) {
	super(name, Type.A, dclass, ttl);
}

static ARecord
getMember() {
	return member;
}

/**
 * Creates an A Record from the given data
 * @param address The address that the name refers to
 */
public
ARecord(Name name, short dclass, int ttl, InetAddress address) 
throws IOException
{
	this(name, dclass, ttl);
	this.addr = address.getAddress();
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	ARecord rec = new ARecord(name, dclass, ttl);

	if (in == null)
		return rec;

	rec.addr = new byte[4];
	in.read(addr);
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	ARecord rec = new ARecord(name, dclass, ttl);
	String s = st.nextToken();
	try {
		InetAddress address;
		if (s.equals("@me@")) {
			address = InetAddress.getLocalHost();
			if (address.equals(InetAddress.getByName("127.0.0.1")))
			{
				String msg = "InetAddress.getLocalHost() is " +
					     "broken.  Don't use @me@.";
				throw new RuntimeException(msg);
			}
		} else {
			if (!Address.isDottedQuad(s)) {
				String error = "invalid dotted quad";
				throw new TextParseException(error);
			}
			address = Address.getByName(s);
		}
		rec.addr = address.getAddress();
	}
	catch (UnknownHostException e) {
		throw new TextParseException("invalid address");
	}
	return rec;
}

/** Converts rdata to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (addr != null) {
		for (int i = 0; i < addr.length; i++) {
			sb.append(addr[i] & 0xFF);
			if (i < addr.length - 1)
				sb.append(".");
		}
	}
	return sb.toString();
}

/** Returns the Internet address */
public InetAddress
getAddress() {
	String s = Address.toDottedQuad(addr);
	try {
		return InetAddress.getByName(s);
	}
	catch (UnknownHostException e) {
		return null;
	}
}

void
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (addr == null)
		return;

	out.write(addr);
}

}
