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

private InetAddress address;

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
	address = _address;
}

ARecord(Name _name, short _dclass, int _ttl, int length,
	DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.A, _dclass, _ttl);

	if (in == null)
		return;

	byte [] data = new byte[4];
	in.read(data);

	String s;
	s = (data[0] & 0xFF) + "." + (data[1] & 0xFF) + "." +
	    (data[2] & 0xFF)  + "." + (data[3] & 0xFF);
	address = InetAddress.getByName(s);
}

ARecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, Type.A, _dclass, _ttl);
	String s = st.nextToken();
	if (s.equals("@me@")) {
		try {
			address = InetAddress.getLocalHost();
			if (address.equals(InetAddress.getByName("127.0.0.1")))
			{
				System.err.println("InetAddress.getLocalHost() is broken.  For now, don't use @me@");
				System.exit(-1);
			}
		}
		catch (UnknownHostException e) {
			address = null;
		}
	}
	else
		address = InetAddress.getByName(s);
}

/** Converts to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
	if (address != null)
		sb.append(address.getHostAddress());
	return sb.toString();
}

/** Returns the Internet address */
public InetAddress
getAddress() {
	return address;
}

void
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (address == null)
		return;

	out.write(address.getAddress());
}

}
