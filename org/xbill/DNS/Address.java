// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.net.*;
import java.net.Inet6Address;
import java.util.*;

/**
 * Routines dealing with IP addresses.  Includes functions similar to
 * those in the java.net.InetAddress class.
 *
 * @author Brian Wellington
 */

public final class Address {

public static final int IPv4 = 1;
public static final int IPv6 = 2;

private
Address() {}

private static byte []
parseV4(String s) {
	int numDigits;
	int currentOctet;
	byte [] values = new byte[4];
	int currentValue;
	int length = s.length();

	currentOctet = 0;
	currentValue = 0;
	numDigits = 0;
	for (int i = 0; i < length; i++) {
		char c = s.charAt(i);
		if (c >= '0' && c <= '9') {
			/* Can't have more than 3 digits per octet. */
			if (numDigits == 3)
				return null;
			/* Octets shouldn't start with 0, unless they are 0. */
			if (numDigits > 0 && currentValue == 0)
				return null;
			numDigits++;
			currentValue *= 10;
			currentValue += (c - '0');
			/* 255 is the maximum value for an octet. */
			if (currentValue > 255)
				return null;
		} else if (c == '.') {
			/* Can't have more than 3 dots. */
			if (currentOctet == 3)
				return null;
			/* Two consecutive dots are bad. */
			if (numDigits == 0)
				return null;
			values[currentOctet++] = (byte) currentValue;
			currentValue = 0;
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
	values[currentOctet] = (byte) currentValue;
	return values;
}

private static byte []
parseV6(String s) {
	boolean parsev4 = false;
	List l = new ArrayList();
	int range = -1;

	byte [] data = new byte[16];

	StringTokenizer st = new StringTokenizer(s, ":", true);
	while (st.hasMoreTokens())
		l.add(st.nextToken());
	l.add("");
	l.add("");

	String [] tokens = (String []) l.toArray(new String[l.size()]);

	int i = 0, j = 0;
	while (i < tokens.length - 2) {
		if (tokens[i].equals(":")) {
			if (tokens[i+1].equals(":")) {
				if (tokens[i+2].equals(":") || range >= 0)
					return null;
				range = j;
				if (tokens[i+2].equals(""))
					break;
				i++;
			}
			i++;
		}

		if (tokens[i].indexOf('.') >= 0) {
			parsev4 = true;
			if (!tokens[i+1].equals(""))
				return null;
			break;
		}

		try {
			int x = Integer.parseInt(tokens[i], 16);
			if (x > 0xFFFF || x < 0)
				return null;
			if (j > 16 - 2)
				return null;
			data[j++] = (byte)(x >>> 8);
			data[j++] = (byte)(x & 0xFF);
		}
		catch (NumberFormatException e) {
			return null;
		}
		i++;
	}

	if (parsev4) {
		byte [] v4addr = Address.toByteArray(tokens[i], IPv4);
		if (v4addr == null)
			return null;
		for (int k = 0; k < 4; k++)
			data[j++] = v4addr[k];
	}
	if (range >= 0) {
		int left = 16 - j;
		for (int k = 15; k >= 0; k--) {
			if (k >= range + left)
				data[k] = data[k - left];
			else if (k >= range)
				data[k] = 0;
		}
	} else if (j < 16)
		return null;
	return data;
}

/**
 * Convert a string containing an IP address to an array of 4 or 16 integers.
 * @param s The address, in text format.
 * @param family The address family.
 * @return The address
 */
public static int []
toArray(String s, int family) {
	byte [] byteArray = toByteArray(s, family);
	if (byteArray == null)
		return null;
	int [] intArray = new int[byteArray.length];
	for (int i = 0; i < byteArray.length; i++)
		intArray[i] = byteArray[i] & 0xFF;
	return intArray;
}

/**
 * Convert a string containing an IPv4 address to an array of 4 integers.
 * @param s The address, in text format.
 * @return The address
 */
public static int []
toArray(String s) {
	return toArray(s, IPv4);
}

/**
 * Convert a string containing an IP address to an array of 4 or 16 bytes.
 * @param s The address, in text format.
 * @param family The address family.
 * @return The address
 */
public static byte []
toByteArray(String s, int family) {
	if (family == IPv4)
		return parseV4(s);
	else if (family == IPv6)
		return parseV6(s);
	else
		throw new IllegalArgumentException("unknown address family");
}

/**
 * Determines if a string contains a valid IP address.
 * @param s The string
 * @return Whether the string contains a valid IP address
 */
public static boolean
isDottedQuad(String s) {
	byte [] address = Address.toByteArray(s, IPv4);
	return (address != null);
}

/**
 * Converts a byte array containing an IPv4 address into a dotted quad string.
 * @param addr The array
 * @return The string representation
 */
public static String
toDottedQuad(byte [] addr) {
	return ((addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "." +
		(addr[2] & 0xFF) + "." + (addr[3] & 0xFF));
}

/**
 * Converts an int array containing an IPv4 address into a dotted quad string.
 * @param addr The array
 * @return The string representation
 */
public static String
toDottedQuad(int [] addr) {
	return (addr[0] + "." + addr[1] + "." + addr[2] + "." + addr[3]);
}

private static Record []
lookupHostName(String name) throws UnknownHostException {
	try {
		Record [] records = new Lookup(name).run();
		if (records == null)
			throw new UnknownHostException("unknown host");
		return records;
	}
	catch (TextParseException e) {
		throw new UnknownHostException("invalid name");
	}
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
	Record [] records = lookupHostName(name);
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
	Record [] records = lookupHostName(name);
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
	Name name = ReverseMap.fromAddress(addr);
	Record [] records = new Lookup(name, Type.PTR).run();
	if (records == null)
		throw new UnknownHostException("unknown address");
	PTRRecord ptr = (PTRRecord) records[0];
	return ptr.getTarget().toString();
}

/**
 * Returns the family of an InetAddress.
 * @param address The supplied address.
 * @return The family, either IPv4 or IPv6.
 */
public static int
familyOf(InetAddress address) {
	if (address instanceof Inet4Address)
		return IPv4;
	if (address instanceof Inet6Address)
		return IPv6;
	throw new IllegalArgumentException("unknown address family");
}

/**
 * Returns the family of an InetAddress.
 * @param family The address family, either IPv4 or IPv6.
 * @return The length of addresses in that family.
 */
public static int
addressLength(int family) {
	if (family == IPv4)
		return 4;
	if (family == IPv6)
		return 16;
	throw new IllegalArgumentException("unknown address family");
}

}
