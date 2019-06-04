// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.net.*;
import java.io.*;

/**
 * Address Record - maps a domain name to an Internet address
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and Specification</a>
 */
public class ARecord extends Record {

private static final long serialVersionUID = -2172609200849142323L;

private int addr;

ARecord() {}

@Override
Record
getObject() {
	return new ARecord();
}

private static int
fromArray(byte [] array) {
	return (((array[0] & 0xFF) << 24) |
		((array[1] & 0xFF) << 16) |
		((array[2] & 0xFF) << 8) |
		(array[3] & 0xFF));
}

private static byte []
toArray(int addr) {
	byte [] bytes = new byte[4];
	bytes[0] = (byte) ((addr >>> 24) & 0xFF);
	bytes[1] = (byte) ((addr >>> 16) & 0xFF);
	bytes[2] = (byte) ((addr >>> 8) & 0xFF);
	bytes[3] = (byte) (addr & 0xFF);
	return bytes;
}

/**
 * Creates an A Record from the given data
 * @param address The address that the name refers to
 */
public
ARecord(Name name, int dclass, long ttl, InetAddress address) {
	super(name, Type.A, dclass, ttl);
	if (Address.familyOf(address) != Address.IPv4)
		throw new IllegalArgumentException("invalid IPv4 address");
	addr = fromArray(address.getAddress());
}

@Override
void
rrFromWire(DNSInput in) throws IOException {
	addr = fromArray(in.readByteArray(4));
}

@Override
void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	addr = fromArray(st.getAddressBytes(Address.IPv4));
}

/** Converts rdata to a String */
@Override
String
rrToString() {
	return (Address.toDottedQuad(toArray(addr)));
}

/** Returns the Internet address */
public InetAddress
getAddress() {
	try {
		if (name == null)
			return InetAddress.getByAddress(toArray(addr));
		else
			return InetAddress.getByAddress(name.toString(),
							toArray(addr));
	} catch (UnknownHostException e) {
		return null;
	}
}

@Override
void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	out.writeU32(((long)addr) & 0xFFFFFFFFL);
}

}
