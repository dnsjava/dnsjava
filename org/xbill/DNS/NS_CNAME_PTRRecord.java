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

void
rrFromWire(DNSInput in) throws IOException {
	target = new Name(in);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	target = st.getName(origin);
}

/** Converts the NS, CNAME, or PTR Record to a String */
String
rrToString() {
	return target.toString();
}

/** Gets the target of the NS, CNAME, or PTR Record */
public Name
getTarget() {
	return target;
}

void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	if (target == null)
		return;

	if (type == Type.DNAME)
		target.toWire(out, null, canonical);
	else
		target.toWire(out, c, canonical);
}

}
