// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

/* High level API */

package DNS;

import java.io.*;
import java.net.*;

public final class Address {

public static InetAddress
getByName(String name) throws UnknownHostException {
	Record [] records = dns.getRecords(name, Type.A);
	if (records == null)
		throw new UnknownHostException("unknown host");
	ARecord a = (ARecord) records[0];
	return a.getAddress();
}

public static InetAddress []
getAllByName(String name) throws UnknownHostException {
	Record [] records = dns.getRecords(name, Type.A);
	if (records == null)
		throw new UnknownHostException("unknown host");
	InetAddress [] addrs = new InetAddress[records.length];
	for (int i = 0; i < records.length; i++) {
		ARecord a = (ARecord) records[i];
		addrs[i] = a.getAddress();
	}
	return addrs;
}

public static String
getHostName(InetAddress addr) throws UnknownHostException {
	Record [] records = dns.getRecordsByAddress(addr.getHostAddress(),
						    Type.PTR);
	if (records == null)
		throw new UnknownHostException("unknown address");
	PTRRecord ptr = (PTRRecord) records[0];
	return ptr.getTarget().toString();
}

}
