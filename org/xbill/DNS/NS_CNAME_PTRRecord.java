// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Implements NS, CNAME, PTR, and DNAME records, which have identical formats 
 *
 * @author Brian Wellington
 */

public abstract class NS_CNAME_PTRRecord extends Record {

protected Name target;

protected
NS_CNAME_PTRRecord() {}

protected
NS_CNAME_PTRRecord(Name name, short type, short dclass, int ttl) {
	super(name, type, dclass, ttl);
}

public
NS_CNAME_PTRRecord(Name name, short type, short dclass, int ttl, Name target) {
	super(name, type, dclass, ttl);
	this.target = target;
}

protected static Record
rrFromWire(NS_CNAME_PTRRecord rec, DataByteInputStream in)
throws IOException
{
	if (in == null)
		return rec;
	rec.target = new Name(in);
	return rec;
}

protected static Record
rdataFromString(NS_CNAME_PTRRecord rec, MyStringTokenizer st, Name origin)
throws TextParseException
{
	rec.target = Name.fromString(st.nextToken(), origin);
	rec.target.checkAbsolute("read an NS, CNAME, PTR, or similar record");
	return rec;
}

/** Converts the NS, CNAME, or PTR Record to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (target != null)
		sb.append(target);
	return sb.toString();
}

/** Gets the target of the NS, CNAME, or PTR Record */
public Name
getTarget() {
	return target;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (target == null)
		return;

	if (type == Type.DNAME)
		target.toWire(out, null, canonical);
	else
		target.toWire(out, c, canonical);
}

}
