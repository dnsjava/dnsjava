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

private int addr;

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

private static final int
fromBytes(byte b1, byte b2, byte b3, byte b4) {
	return (((b1 & 0xFF) << 24) |
		((b2 & 0xFF) << 16) |
		((b3 & 0xFF) << 8) |
		(b4 & 0xFF));
}

private static final int
fromArray(byte [] array) {
	return (fromBytes(array[0], array[1], array[2], array[3]));
}

private static final String
toDottedQuad(int addr) {
	StringBuffer sb = new StringBuffer();
	sb.append(((addr >>> 24) & 0xFF));
	sb.append(".");
	sb.append(((addr >>> 16) & 0xFF));
	sb.append(".");
	sb.append(((addr >>> 8) & 0xFF));
	sb.append(".");
	sb.append((addr & 0xFF));
	return sb.toString();
}

/**
 * Creates an A Record from the given data
 * @param address The address that the name refers to
 */
public
ARecord(Name name, short dclass, int ttl, InetAddress address) {
	this(name, dclass, ttl);
	addr = fromArray(address.getAddress());
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	ARecord rec = new ARecord(name, dclass, ttl);

	if (in == null)
		return rec;

	byte b1 = in.readByte();
	byte b2 = in.readByte();
	byte b3 = in.readByte();
	byte b4 = in.readByte();
	rec.addr = fromBytes(b1, b2, b3, b4);
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	ARecord rec = new ARecord(name, dclass, ttl);
	String s = nextString(st);
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
			if (!Address.isDottedQuad(s))
				throw new TextParseException
						("invalid dotted quad");
			address = Address.getByName(s);
		}
		rec.addr = fromArray(address.getAddress());
	}
	catch (UnknownHostException e) {
		throw new TextParseException("invalid address");
	}
	return rec;
}

/** Converts rdata to a String */
public String
rdataToString() {
	return (toDottedQuad(addr));
}

/** Returns the Internet address */
public InetAddress
getAddress() {
	String s = toDottedQuad(addr);
	try {
		return InetAddress.getByName(s);
	}
	catch (UnknownHostException e) {
		return null;
	}
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	out.writeByte(((addr >>> 24) & 0xFF));
	out.writeByte(((addr >>> 16) & 0xFF));
	out.writeByte(((addr >>> 8) & 0xFF));
	out.writeByte((addr & 0xFF));
}

}
