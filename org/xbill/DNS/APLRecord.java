// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * APL - Address Prefix List.
 *
 * @author Brian Wellington
 */

public class APLRecord extends Record {

public static class AddressFamily {
	private AddressFamily() {}

	public static final int IPv4 = 1;
	public static final int IPv6 = 2;
}

public static class Element {
	public final int family;
	public final boolean negative;
	public final int prefixLength;
	public final Object address;


	private
	Element(int family, boolean negative, Object address, int prefixLength)
	{
		this.family = family;
		this.negative = negative;
		this.address = address;
		this.prefixLength = prefixLength;
		if (!validatePrefixLength(family, prefixLength)) {
			throw new IllegalArgumentException("invalid prefix " +
							   "length");
		}
	}

	/**
	 * Creates an APL element corresponding to an IPv4 prefix.
	 * @param negative Indicates if this prefix is a negation.
	 * @param address The IPv4 address.
	 * @param negative The prefix length.
	 * @throws IllegalArgumentException The prefix length is invalid.
	 */
	public
	Element(boolean negative, InetAddress address, int prefixLength) {
		this(AddressFamily.IPv4, negative, address, prefixLength);
	}

	/**
	 * Creates an APL element corresponding to an IPv6 prefix.
	 * @param negative Indicates if this prefix is a negation.
	 * @param address The IPv6 address.
	 * @param negative The prefix length.
	 * @throws IllegalArgumentException The prefix length is invalid.
	 */
	public
	Element(boolean negative, Inet6Address address, int prefixLength) {
		this(AddressFamily.IPv6, negative, address, prefixLength);
	}
	
	public String
	toString() {
		StringBuffer sb = new StringBuffer();
		if (negative)
			sb.append("!");
		sb.append(family);
		sb.append(":");
		if (family == AddressFamily.IPv4)
			sb.append(((InetAddress) address).getHostAddress());
		else if (family == AddressFamily.IPv6)
			sb.append((Inet6Address) address);
		else
			sb.append(base16.toString((byte []) address));
		sb.append("/");
		sb.append(prefixLength);
		return sb.toString();
	}
}

private List elements;

APLRecord() {} 

Record
getObject() {
	return new APLRecord();
}

private static boolean
validatePrefixLength(int family, int prefixLength) {
	if (prefixLength < 0 || prefixLength >= 256)
		return false;
	if ((family == AddressFamily.IPv4 && prefixLength > 32) ||
	    (family == AddressFamily.IPv6 && prefixLength > 128))
		return false;
	return true;
}

/**
 * Creates an APL Record from the given data.
 * @param elements The list of APL elements.
 */
public
APLRecord(Name name, int dclass, long ttl, List elements) {
	super(name, Type.APL, dclass, ttl);
	this.elements = new ArrayList(elements.size());
	for (Iterator it = elements.iterator(); it.hasNext(); ) {
		Object o = it.next();
		if (!(o instanceof Element)) {
			throw new IllegalArgumentException("illegal element");
		}
		Element element = (Element) o;
		if (element.family != AddressFamily.IPv4 &&
		    element.family != AddressFamily.IPv6)
		{
			throw new IllegalArgumentException("unknown family");
		}
		this.elements.add(element);

	}
}

private static byte []
parseAddress(byte [] in, int length) throws WireParseException {
	if (in.length > length)
		throw new WireParseException("invalid address length");
	if (in.length == length)
		return in;
	byte [] out = new byte[length];
	System.arraycopy(in, 0, out, 0, in.length);
	return out;
}

void
rrFromWire(DNSInput in) throws IOException {
	elements = new ArrayList(1);
	while (in.remaining() != 0) {
		int family = in.readU16();
		int prefix = in.readU8();
		int length = in.readU8();
		boolean negative = (length & 0x80) != 0;
		length &= ~0x80;

		byte [] data = in.readByteArray(length);
		Element element;
		if (!validatePrefixLength(family, prefix)) {
			throw new WireParseException("invalid prefix length");
		}

		if (family == AddressFamily.IPv4) {
			data = parseAddress(data, 4);
			String s = Address.toDottedQuad(data);
			InetAddress addr = Address.getByName(s);
			element = new Element(negative, addr, prefix);
		} else if (family == AddressFamily.IPv6) {
			data = parseAddress(data, 16);
			Inet6Address addr = new Inet6Address(data);
			element = new Element(negative, addr, prefix);
		} else {
			element = new Element(family, negative, data, prefix);
		}
		elements.add(element);

	}
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	elements = new ArrayList(1);
	while (true) {
		Tokenizer.Token t = st.get();
		if (!t.isString())
			break;

		boolean negative = false;
		int family = 0;
		int prefix = 0;

		String s = t.value;
		int start = 0;
		if (s.startsWith("!")) {
			negative = true;
			start = 1;
		}
		int colon = s.indexOf(':', start);
		if (colon < 0)
			throw st.exception("invalid address prefix element");
		int slash = s.indexOf('/', colon);
		if (slash < 0)
			throw st.exception("invalid address prefix element");

		String familyString = s.substring(start, colon);
		String addressString = s.substring(colon + 1, slash);
		String prefixString = s.substring(slash + 1);

		try {
			family = Integer.parseInt(familyString);
		}
		catch (NumberFormatException e) {
			throw st.exception("invalid family");
		}
		if (family != 1 && family != 2) {
			throw st.exception("unknown family");
		}

		try {
			prefix = Integer.parseInt(prefixString);
		}
		catch (NumberFormatException e) {
			throw st.exception("invalid prefix length");
		}

		if (!validatePrefixLength(family, prefix)) {
			throw st.exception("invalid prefix length");
		}

		if (family == AddressFamily.IPv4) {
			if (!Address.isDottedQuad(addressString)) {
				throw st.exception("invalid IPv4 address " +
						   addressString);
			}
			InetAddress address = Address.getByName(addressString);
			elements.add(new Element(negative, address, prefix));
		} else if (family == AddressFamily.IPv6) {
			Inet6Address address = null;
			try {
				address = new Inet6Address(addressString);
			} catch (TextParseException e) {
				throw st.exception(e.getMessage());
			}
			elements.add(new Element(negative, address, prefix));
		} else {
			throw new IllegalStateException();
		}
	}
	st.unget();
}

String
rrToString() {
	StringBuffer sb = new StringBuffer();
	for (Iterator it = elements.iterator(); it.hasNext(); ) {
		Element element = (Element) it.next();
		sb.append(element);
		if (it.hasNext())
			sb.append(" ");
	}
	return sb.toString();
}

/** Returns the list of APL elements. */
public List
getElements() {
	return elements;
}

private static int
addressLength(byte [] addr) {
	for (int i = addr.length - 1; i >= 0; i--) {
		if (addr[i] != 0)
			return i + 1;
	}
	return 0;
}

void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	for (Iterator it = elements.iterator(); it.hasNext(); ) {
		Element element = (Element) it.next();
		int length = 0;
		byte [] data;
		if (element.family == AddressFamily.IPv4) {
			InetAddress addr = (InetAddress) element.address;
			data = addr.getAddress();
			length = addressLength(data);
		} else if (element.family == AddressFamily.IPv6) {
			Inet6Address addr = (Inet6Address) element.address;
			data = addr.toBytes();
			length = addressLength(data);
		} else {
			data = (byte []) element.address;
			length = data.length;
		}
		int wlength = length;
		if (element.negative) {
			wlength |= 0x80;
		}
		out.writeU16(element.family);
		out.writeU8(element.prefixLength);
		out.writeU8(wlength);
		out.writeByteArray(data, 0, length);
	}
}

}
