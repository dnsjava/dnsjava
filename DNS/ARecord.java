// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.net.*;
import java.io.*;
import java.util.*;

public class dnsARecord extends dnsRecord {

InetAddress address;

public
dnsARecord(dnsName _name, short _dclass, int _ttl, InetAddress _address) 
throws IOException
{
	super(_name, dns.A, _dclass, _ttl);
	address = _address;
}

public
dnsARecord(dnsName _name, short _dclass, int _ttl, int length,
	   CountedDataInputStream in, dnsCompression c) throws IOException
{
	super(_name, dns.A, _dclass, _ttl);

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
dnsARecord(dnsName _name, short _dclass, int _ttl, MyStringTokenizer st,
	   dnsName origin)
throws IOException
{
	super(_name, dns.A, _dclass, _ttl);
	String s = st.nextToken();
	if (s.equals("@me@")) {
		try {
			address = InetAddress.getLocalHost();
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
rrToWire(dnsCompression c) {
	if (address == null)
		return null;
	else
		return address.getAddress();
}

}
