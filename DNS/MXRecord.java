// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class MXRecord extends Record {

short priority;
Name target;

public
MXRecord(Name _name, short _dclass, int _ttl, int _priority, Name _target)
{
	super(_name, Type.MX, _dclass, _ttl);
	priority = (short) _priority;
	target = _target;
}

public
MXRecord(Name _name, short _dclass, int _ttl,
	    int length, CountedDataInputStream in, Compression c)
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

public Name
getTarget() {
	return target;
}

public short
getPriority() {
	return priority;
}

byte []
rrToWire(Compression c) throws IOException {
	if (target == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	CountedDataOutputStream ds = new CountedDataOutputStream(bs);

	ds.writeShort(priority);
	target.toWire(ds, null);
	return bs.toByteArray();
}

}
