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

public class MX_KXRecord extends Record {

private short priority;
private Name target;

protected
MX_KXRecord() {}

public
MX_KXRecord(Name _name, short _type, short _dclass, int _ttl, int _priority,
	    Name _target)
{
	super(_name, _type, _dclass, _ttl);
	priority = (short) _priority;
	target = _target;
}

protected
MX_KXRecord(Name _name, short _type, short _dclass, int _ttl,
	    int length, DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, _type, _dclass, _ttl);
	if (in == null)
		return;
	priority = (short) in.readUnsignedShort();
	target = new Name(in, c);
}

protected
MX_KXRecord(Name _name, short _type, short _dclass, int _ttl,
	    MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, _type, _dclass, _ttl);
	priority = Short.parseShort(st.nextToken());
	target = new Name(st.nextToken(), origin);
}

/** Converts to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (target == null)
		return;

	out.writeShort(priority);
	target.toWire(out, null);
}

void
rrToWireCanonical(DataByteOutputStream out) throws IOException {
	if (target == null)
		return;

	out.writeShort(priority);
	target.toWireCanonical(out);
}

}
