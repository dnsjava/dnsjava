// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Implements NS, CNAME, PTR, and DNAME records, which have identical formats 
 *
 * @author Brian Wellington
 */

abstract class NS_CNAME_PTRRecord extends Record {

protected Name target;

protected
NS_CNAME_PTRRecord() {}

protected
NS_CNAME_PTRRecord(Name name, int type, int dclass, long ttl) {
	super(name, type, dclass, ttl);
}

public
NS_CNAME_PTRRecord(Name name, int type, int dclass, long ttl, Name target) {
	super(name, type, dclass, ttl);
	if (!target.isAbsolute())
		throw new RelativeNameException(target);
	this.target = target;
}

protected static Record
rrFromWire(NS_CNAME_PTRRecord rec, DNSInput in)
throws IOException
{
	if (in == null)
		return rec;
	rec.target = new Name(in);
	return rec;
}

protected static Record
rdataFromString(NS_CNAME_PTRRecord rec, Tokenizer st, Name origin)
throws IOException
{
	rec.target = st.getName(origin);
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
