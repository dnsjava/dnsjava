// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Implements MX and KX records, which have identical formats
 *
 * @author Brian Wellington
 */

abstract class MX_KXRecord extends Record {

protected int priority;
protected Name target;

protected
MX_KXRecord() {}

protected
MX_KXRecord(Name name, int type, int dclass, long ttl) {
	super(name, type, dclass, ttl);
}

public
MX_KXRecord(Name name, int type, int dclass, long ttl, int priority,
	    Name target)
{
	super(name, type, dclass, ttl);
	this.priority = checkU16("priority", priority);
	this.target = checkName("target", target);
}

void
rrFromWire(DNSInput in) throws IOException {
	priority = in.readU16();
	target = new Name(in);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	priority = st.getUInt16();
	target = st.getName(origin);
}

/** Converts rdata to a String */
String
rrToString() {
	StringBuffer sb = new StringBuffer();
	sb.append(priority);
	sb.append(" ");
	sb.append(target);
	return sb.toString();
}

/** Returns the target of the record */
public Name
getTarget() {
	return target;
}

/** Returns the priority of this record */
public int
getPriority() {
	return priority;
}

void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	out.writeU16(priority);
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
