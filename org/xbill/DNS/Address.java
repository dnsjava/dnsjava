// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import org.xbill.DNS.utils.*;

/**
 * A simple clone of the java.net.InetAddress class, using dnsjava routines.
 *
 * @author Brian Wellington
 */

public final class Address {

private
Address() {}

/**
 * Convert a string containing an IP address to an array of 4 integers.
 * @param s The string
 * @return The address
 */
public static int []
toArray(String s) {
	int numDigits;
	int currentOctet;
	int [] values = new int[4];
	int length = s.length();

	currentOctet = 0;
	numDigits = 0;
	for (int i = 0; i < length; i++) {
		char c = s.charAt(i);
		if(c >= '0' && c <= '9') {
			/* Can't have more than 3 digits per octet. */
			if (numDigits == 3)
				return null;
			numDigits++;
			values[currentOctet] *= 10;
			values[currentOctet] += (c - '0');
			/* 255 is the maximum value for an octet. */
			if (values[currentOctet] > 255)
				return null;
		} else if (c == '.') {
			/* Can't have more than 3 dots. */
			if (currentOctet == 3)
				return null;
			/* Two consecutive dots are bad. */
			if (numDigits == 0)
				return null;
			currentOctet++;
			numDigits = 0;
		} else
			return null;
	}
	/* Must have 4 octets. */
	if (currentOctet != 3)
		return null;
	/* The fourth octet can't be empty. */
	if (numDigits == 0)
		return null;
	return values;
}

/**
 * Determines if a string contains a valid IP address.
 * @param s The string
 * @return Whether the string contains a valid IP address
 */
public static boolean
isDottedQuad(String s) {
	int [] address = Address.toArray(s);
	return (address != null);
}

/**
 * Converts a byte array containing an IPv4 address into a dotted quad string.
 * @param attr The byte array
 * @return The string representation
 */
public static String
toDottedQuad(byte [] addr) {
	return ((addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "." +
		(addr[2] & 0xFF) + "." + (addr[3] & 0xFF));

}

/**
 * Determines the IP address of a host
 * @param name The hostname to look up
 * @return The first matching IP address
 * @exception UnknownHostException The hostname does not have any addresses
 */
public static InetAddress
getByName(String name) throws UnknownHostException {
	if (isDottedQuad(name))
		return InetAddress.getByName(name);
	Record [] records = dns.getRecords(name, Type.A);
	if (records == null)
		throw new UnknownHostException("unknown host");
	ARecord a = (ARecord) records[0];
	return a.getAddress();
}

/**
 * Determines all IP address of a host
 * @param name The hostname to look up
 * @return All matching IP addresses
 * @exception UnknownHostException The hostname does not have any addresses
 */
public static InetAddress []
getAllByName(String name) throws UnknownHostException {
	if (isDottedQuad(name))
		return InetAddress.getAllByName(name);
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
 * @return The associated host name
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
