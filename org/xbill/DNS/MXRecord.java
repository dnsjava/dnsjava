// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

/** Mail Exchange - specifies where mail to a domain is sent */

public class MXRecord extends Record {

private short priority;
private Name target;

private
MXRecord() {}

/**
 * Creates an MX Record from the given data
 * @param priority The priority of this MX.  Records with lower priority
 * are preferred.
 * @param target The host that mail is sent to
 */
public
MXRecord(Name _name, short _dclass, int _ttl, int _priority, Name _target)
{
	super(_name, Type.MX, _dclass, _ttl);
	priority = (short) _priority;
	target = _target;
}

public
MXRecord(Name _name, short _dclass, int _ttl,
	    int length, DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.MX, _dclass, _ttl);
	if (in == null)
		return;
	priority = (short) in.readUnsignedShort();
	target = new Name(in, c);
}

public
MXRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, Type.MX, _dclass, _ttl);
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

/** Returns the host that mail is sent to */
public Name
getTarget() {
	return target;
}

/** Returns the priority of this MX */
public short
getPriority() {
	return priority;
}

void
rrToWire(DataByteOutputStream dbs, Compression c) throws IOException {
	if (target == null)
		return;

	dbs.writeShort(priority);
	target.toWire(dbs, null);
}

}
