// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

/* High level API */

package org.xbill.DNS;

import java.util.*;
import java.net.*;

/**
 * A set functions designed to deal with DNS names used in reverse mappings.
 * For an IP address a.b.c.d, the reverse map name is d.c.b.a.in-addr.arpa.
 *
 * @author Brian Wellington
 */

public final class ReverseMap {

private static Name inaddr = Name.fromConstantString("in-addr.arpa.");

/* Otherwise the class could be instantiated */
private
ReverseMap() {}

/**
 * Creates a reverse map name corresponding to an address contained in
 * an array of 4 integers.
 * @param addr The address from which to build a name.
 * @return The name corresponding to the address in the reverse map.
 */
public static Name
fromAddress(int [] addr) {
	if (addr.length != 4)
		throw new IllegalArgumentException("array must contain " +
						   "4 elements");
	StringBuffer sb = new StringBuffer();
	for (int i = 3; i >= 0; i--) {
		if (addr[i] < 0 || addr[i] > 0xFF)
			throw new IllegalArgumentException("array must " +
							   "contain values " +
							   "between 0 and 255");
		sb.append(addr[i]);
		if (i > 0)
			sb.append(".");
	}
	try {
		return Name.fromString(sb.toString(), inaddr);
	}
	catch (TextParseException e) {
		throw new IllegalStateException("name cannot be invalid");
	}
}

/**
 * Creates a reverse map name corresponding to an address contained in
 * an InetAddress.
 * @param addr The address from which to build a name.
 * @return The name corresponding to the address in the reverse map.
 */
public static Name
fromAddress(InetAddress addr) {
	byte [] bytes = addr.getAddress();
	int [] array = new int[4];
	for (int i = 0; i < 3; i ++) {
		array[i] = bytes[3 - i] & 0xFF;
	}
	return fromAddress(array);
}

/**
 * Creates a reverse map name corresponding to an address contained in
 * a String.
 * @param addr The address from which to build a name.
 * @return The name corresponding to the address in the reverse map.
 * @throws UnknownHostException The string does not contain a valid address.
 */
public static Name
fromAddress(String addr) throws UnknownHostException {
	int [] array = Address.toArray(addr);
	if (array == null)
		throw new UnknownHostException("Invalid IP address");
	return fromAddress(array);
}

}
