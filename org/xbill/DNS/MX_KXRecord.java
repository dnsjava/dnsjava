// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Implements MX and KX records, which have identical formats
 *
 * @author Brian Wellington
 */

public abstract class MX_KXRecord extends Record {

protected short priority;
protected Name target;

protected
MX_KXRecord() {}

protected
MX_KXRecord(Name name, short type, short dclass, int ttl) {
	super(name, type, dclass, ttl);
}

public
MX_KXRecord(Name name, short type, short dclass, int ttl, int priority,
	    Name target)
{
	super(name, type, dclass, ttl);
	this.priority = (short) priority;
	this.target = target;
}

protected static Record
rrFromWire(MX_KXRecord rec, DataByteInputStream in)
throws IOException
{
	if (in == null)
		return rec;
	rec.priority = (short) in.readUnsignedShort();
	rec.target = new Name(in);
	return rec;
}

protected static Record
rdataFromString(MX_KXRecord rec, MyStringTokenizer st, Name origin)
throws TextParseException
{
	rec.priority = Short.parseShort(nextString(st));
	rec.target = Name.fromString(nextString(st), origin);
	rec.target.checkAbsolute("read an MX or KX record");
	return rec;
}

/** Converts rdata to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (target != null) {
		sb.append(priority);
		sb.append(" ");
		sb.append(target);
	}
	return sb.toString();
}

/** Returns the target of the record */
public Name
getTarget() {
	return target;
}

/** Returns the priority of this record */
public short
getPriority() {
	return priority;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (target == null)
		return;

	out.writeShort(priority);
	if (type == Type.MX)
		target.toWire(out, c, canonical);
	else
		target.toWire(out, null, canonical);
}

public Name
getAdditionalName() {
	return target;
}

}
