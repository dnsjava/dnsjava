// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.net.*;

/** A simple clone of the java.net.InetAddress class, using dnsjava routines */

public final class Address {

/**
 * Determines the IP address of a host
 * @param name The hostname to look up
 * @return name The first matching IP address
 * @exception UnknownHostException The hostname does not have any addresses
 */
public static InetAddress
getByName(String name) throws UnknownHostException {
	Record [] records = dns.getRecords(name, Type.A);
	if (records == null)
		throw new UnknownHostException("unknown host");
	ARecord a = (ARecord) records[0];
	return a.getAddress();
}

/**
 * Determines all IP address of a host
 * @param name The hostname to look up
 * @return name All matching IP addresses
 * @exception UnknownHostException The hostname does not have any addresses
 */
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

/**
 * Determines the hostname for an address
 * @param addr The address to look up
 * @return name The associated host name
 * @exception UnknownHostException There is no hostname for the address
 */
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
