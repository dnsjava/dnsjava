// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.net.*;
import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Inet6Address - implementation of IPv6 address
 *
 * @author Brian Wellington
 */

public class Inet6Address {

private byte [] data;

/**
 * Creates an Inet6Address from 128 bits of data
 */
public
Inet6Address(byte [] data) throws IOException
{
	if (data.length != 16)
		throw new IOException("An Inet6Address is 128 bits");
	this.data = data;
}

/**
 * Creates an Inet6Address from fewer than 128 bits of data
 */
public
Inet6Address(int bits, byte [] data) throws IOException
{
	if (data.length > 16)
		throw new IOException("An Inet6Address is only 128 bits");
	int bytes = (bits + 7) / 8;
	this.data = new byte[16];
	System.arraycopy(data, 0, this.data, 16 - bytes, bytes);
}

/**
 * Creates an Inet6Address from text format
 */
public
Inet6Address(String s) throws TextParseException
{
	boolean parsev4 = false;
	List l = new ArrayList();
	int range = -1;

	data = new byte[16];

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
					throw new TextParseException
						("Invalid IPv6 address");
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
				throw new TextParseException
						("Invalid IPv6 address");
			break;
		}

		try {
			int x = Integer.parseInt(tokens[i], 16);
			if (x > 0xFFFF)
				throw new TextParseException
						("Invalid IPv6 address");
			if (j > 16 - 2)
				throw new TextParseException
						("Invalid IPv6 address");
			data[j++] = (byte) (x >>> 8);
			data[j++] = (byte) (x & 0xFF);
		}
		catch (NumberFormatException e) {
			throw new TextParseException
					("Invalid IPv6 address");
		}
		i++;
	}

	if (parsev4) {
		int [] v4addr = Address.toArray(tokens[i]);
		if (v4addr == null)
			throw new TextParseException("Invalid IPv6 address");
		for (int k = 0; k < 4; k++)
			data[j++] = (byte) v4addr[k];
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
		throw new TextParseException("Invalid IPv6 address");
}

public byte[]
toBytes() {
	return data;
}

public String
toString() {
	int [] labels = new int[8];
	StringBuffer sb = new StringBuffer();
	for (int i = 0, j = 0; i < 8; i++)
		labels[i] = ((data[2 * i] & 0xFF) << 8) +
			    (data[2 * i + 1] & 0xFF);
	int start = -1, length = -1, tstart = -1, tlength = -1;
	boolean inzero = false;
	for (int i = 0, j = 0; i < 8; i++) {
		if (!inzero) {
			if (labels[i] == 0) {
				tstart = i;
				tlength = 0;
				inzero = true;
			}
		}
		else {
			if (labels[i] == 0)
				tlength++;
			else {
				inzero = false;
				if (tlength > length) {
					start = tstart;
					length = tlength;
				}
				tlength = -1;
			}
		}
	}
	if (tlength > length) {
		start = tstart;
		length = tlength;
	}

	if (start == -1) {
		for (int i = 0; i < 8; i++) {
			sb.append(Integer.toHexString(labels[i]).toUpperCase());
			if (i != 7)
				sb.append(":");
		}
	}
	else {
		for (int i = 0; i < start; i++) {
			sb.append(Integer.toHexString(labels[i]).toUpperCase());
			sb.append(":");
		}
		if (start == 0)
			sb.append(":");
		sb.append(":");
		for (int i = start + length + 1; i < 8 ; i++) {
			sb.append(Integer.toHexString(labels[i]).toUpperCase());
			if (i != 7)
				sb.append(":");
		}
	}
	return sb.toString();
}

}
