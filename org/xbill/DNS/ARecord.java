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

private byte [] addr;

private
ARecord() {}

/**
 * Creates an A Record from the given data
 * @param address The address that the name refers to
 */
public
ARecord(Name _name, short _dclass, int _ttl, InetAddress _address) 
throws IOException
{
	super(_name, Type.A, _dclass, _ttl);
	addr = _address.getAddress();
}

ARecord(Name _name, short _dclass, int _ttl, int length,
	DataByteInputStream in)
throws IOException
{
	super(_name, Type.A, _dclass, _ttl);

	if (in == null)
		return;

	addr = new byte[4];
	in.read(addr);
}

ARecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, Type.A, _dclass, _ttl);
	String s = st.nextToken();
	if (s.equals("@me@")) {
		try {
			InetAddress address = InetAddress.getLocalHost();
			if (address.equals(InetAddress.getByName("127.0.0.1")))
			{
				String msg = "InetAddress.getLocalHost() is " +
					     "broken.  Don't use @me@.";
				throw new RuntimeException(msg);
			}
		}
		catch (UnknownHostException e) {
			addr = null;
		}
	}
	else {
		if (!Address.isDottedQuad(s))
			throw new IOException("Invalid dotted quad address");
		addr = InetAddress.getByName(s).getAddress();
	}
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
