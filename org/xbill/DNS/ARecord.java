// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.net.*;
import java.io.*;
import java.util.*;
import DNS.utils.*;

public class ARecord extends Record {

InetAddress address;

public
ARecord(Name _name, short _dclass, int _ttl, InetAddress _address) 
throws IOException
{
	super(_name, Type.A, _dclass, _ttl);
	address = _address;
}

public
ARecord(Name _name, short _dclass, int _ttl, int length,
	   CountedDataInputStream in, Compression c) throws IOException
{
	super(_name, Type.A, _dclass, _ttl);

	if (in == null)
		return;

	byte [] data = new byte[4];
	in.read(data);

	String s = new String();
	s = (data[0] & 0xFF) + "." + (data[1] & 0xFF) + "." +
	    (data[2] & 0xFF)  + "." + (data[3] & 0xFF);
	try {
		address = InetAddress.getByName(s);
	}
	catch (UnknownHostException e) {
		System.out.println("Invalid IP address " + s);
	}
}

public
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
				System.out.println("InetAddress.getLocalHost() is broken.  For now, don't use @me@");
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

public String
toString() {
	StringBuffer sb = toStringNoData();
	if (address != null)
		sb.append(address.getHostAddress());
	return sb.toString();
}

public InetAddress
getAddress() {
	return address;
}

byte []
rrToWire(Compression c) {
	if (address == null)
		return null;
	else
		return address.getAddress();
}

}
