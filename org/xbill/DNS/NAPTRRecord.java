// Copyright (c) 2000 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Name Authority Pointer Record  - specifies rewrite rule, that when applied
 * to an existing string will produce a new domain.
 *
 * @author Chuck Santos
 */

public class NAPTRRecord extends Record {

private static NAPTRRecord member = new NAPTRRecord();

private short order, preference;
private String flags, service, regexp;
private Name replacement;

private NAPTRRecord() {}

private
NAPTRRecord(Name name, short dclass, int ttl) {
	super(name, Type.NAPTR, dclass, ttl);
}

static NAPTRRecord
getMember() {
	return member;
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
 */
public
NAPTRRecord(Name name, short dclass, int ttl, int order, int preference,
	    String flags, String service, String regexp, Name replacement)
{
	this(name, dclass, ttl);
	this.order = (short) order;
	this.preference = (short) preference;
	this.flags = flags;
	this.service = service;
	this.regexp = regexp;
	this.replacement = replacement;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	NAPTRRecord rec = new NAPTRRecord(name, dclass, ttl);
	if (in == null)
		return rec;
	rec.order = (short) in.readUnsignedShort();
	rec.preference = (short) in.readUnsignedShort();
	rec.flags = in.readString();
	rec.service = in.readString();
	rec.regexp = in.readString();
	rec.replacement = new Name(in);
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	NAPTRRecord rec = new NAPTRRecord(name, dclass, ttl);
	rec.order = Short.parseShort(nextString(st));
	rec.preference = Short.parseShort(nextString(st));
	rec.flags = nextString(st);
	rec.service = nextString(st);
	rec.regexp = nextString(st);
	rec.replacement = Name.fromString(nextString(st), origin);
	rec.replacement.checkAbsolute("read a NAPTR record");
	return rec;
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
		sb.append(flags);
		sb.append(" ");
		sb.append(service);
		sb.append(" ");
		sb.append(regexp);
		sb.append(" ");
		sb.append(replacement);
	}
	return sb.toString();
}

/** Returns the order */
public short
getOrder() {
	return order;
}

/** Returns the preference */
public short
getPreference() {
	return preference;
}

/** Returns flags */
public String
getFlags() {
	return flags;
}

/** Returns service */
public String
getService() {
	return service;
}

/** Returns regexp */
public String
getRegexp() {
	return regexp;
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
	out.writeString(flags);
	out.writeString(service);
	out.writeString(regexp);
	replacement.toWire(out, null, canonical);
}

public Name
getAdditionalName() {
	return replacement;
}

}
