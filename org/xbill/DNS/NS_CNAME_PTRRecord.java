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

public class NS_CNAME_PTRRecord extends Record {

private Name target;

protected
NS_CNAME_PTRRecord() {}

public
NS_CNAME_PTRRecord(Name _name, short _type, short _dclass, int _ttl,
		   Name _target)
{
	super(_name, _type, _dclass, _ttl);
	target = _target;
}

protected
NS_CNAME_PTRRecord(Name _name, short _type, short _dclass, int _ttl,
		   int length, DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, _type, _dclass, _ttl);
	if (in == null)
		return;
	target = new Name(in, c);
}

protected
NS_CNAME_PTRRecord(Name _name, short _type, short _dclass, int _ttl,
		   MyStringTokenizer st, Name origin)
throws IOException
{
        super(_name, _type, _dclass, _ttl);
        target = new Name(st.nextToken(), origin);
}

/** Converts the NS, CNAME, or PTR Record to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (target == null)
		return;

	if (type == Type.DNAME)
		target.toWire(out, null);
	else
		target.toWire(out, c);
}

void
rrToWireCanonical(DataByteOutputStream out) throws IOException {
	if (target == null)
		return;

	target.toWireCanonical(out);
}

}
