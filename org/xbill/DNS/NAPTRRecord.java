// Copyright (c) 2000-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Name Authority Pointer Record  - specifies rewrite rule, that when applied
 * to an existing string will produce a new domain.
 *
 * @author Chuck Santos
 */

public class NAPTRRecord extends Record {

private int order, preference;
private byte [] flags, service, regexp;
private Name replacement;

NAPTRRecord() {}

Record
getObject() {
	return new NAPTRRecord();
}

/**
 * Creates an NAPTR Record from the given data
 * @param order The order of this NAPTR.  Records with lower order are
 * preferred.
 * @param preference The preference, used to select between records at the
 * same order.
 * @param flags The control aspects of the NAPTRRecord.
 * @param service The service or protocol available down the rewrite path.
 * @param regexp The regular/substitution expression.
 * @param replacement The domain-name to query for the next DNS resource
 * record, depending on the value of the flags field.
 * @throws IllegalArgumentException One of the strings has invalid escapes
 */
public
NAPTRRecord(Name name, int dclass, long ttl, int order, int preference,
	    String flags, String service, String regexp, Name replacement)
{
	super(name, Type.NAPTR, dclass, ttl);
	checkU16("order", order);
	checkU16("preference", preference);
	this.order = order;
	this.preference = order;
	try {
		this.flags = byteArrayFromString(flags);
		this.service = byteArrayFromString(service);
		this.regexp = byteArrayFromString(regexp);
	}
	catch (TextParseException e) {
		throw new IllegalArgumentException(e.getMessage());
	}
	if (!replacement.isAbsolute())
		throw new RelativeNameException(replacement);
	this.replacement = replacement;
}

void
rrFromWire(DNSInput in) throws IOException {
	if (in == null)
		return;

	order = in.readU16();
	preference = in.readU16();
	flags = in.readCountedString();
	service = in.readCountedString();
	regexp = in.readCountedString();
	replacement = new Name(in);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	order = st.getUInt16();
	preference = st.getUInt16();
	try {
		flags = byteArrayFromString(st.getString());
		service = byteArrayFromString(st.getString());
		regexp = byteArrayFromString(st.getString());
	}
	catch (TextParseException e) {
		throw st.exception(e.getMessage());
	}
	replacement = st.getName(origin);
}

/** Converts rdata to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (replacement != null) {
		sb.append(order);
		sb.append(" ");
		sb.append(preference);
		sb.append(" ");
		sb.append(byteArrayToString(flags, true));
		sb.append(" ");
		sb.append(byteArrayToString(service, true));
		sb.append(" ");
		sb.append(byteArrayToString(regexp, true));
		sb.append(" ");
		sb.append(replacement);
	}
	return sb.toString();
}

/** Returns the order */
public int
getOrder() {
	return order;
}

/** Returns the preference */
public int
getPreference() {
	return preference;
}

/** Returns flags */
public String
getFlags() {
	return byteArrayToString(flags, false);
}

/** Returns service */
public String
getService() {
	return byteArrayToString(service, false);
}

/** Returns regexp */
public String
getRegexp() {
	return byteArrayToString(regexp, false);
}

/** Returns the replacement domain-name */
public Name
getReplacement() {
	return replacement;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (replacement == null && regexp == null)
		return;
	out.writeShort(order);
	out.writeShort(preference);
	out.writeArray(flags, true);
	out.writeArray(service, true);
	out.writeArray(regexp, true);
	replacement.toWire(out, null, canonical);
}

public Name
getAdditionalName() {
	return replacement;
}

}
