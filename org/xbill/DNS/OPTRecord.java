// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class OPTRecord extends Record {

Hashtable options;

public
OPTRecord(Name _name, short _dclass, int _ttl) {
	super(_name, Type.OPT, _dclass, _ttl);
	options = null;
}

public
OPTRecord(Name _name, short _dclass, int _ttl,
	  int length, DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.OPT, _dclass, _ttl);
	if (in == null)
		return;
	int count = 0;
	if (count < length)
		options = new Hashtable();
	while (count < length) {
		int code = in.readUnsignedShort();
		int len = in.readUnsignedShort();
		byte [] data = new byte[len];
		in.read(data);
		count += (4 + len);
		options.put(new Integer(code), data);
	}
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	Enumeration e = options.keys();
	while (e.hasMoreElements()) {
		Integer i = (Integer) e.nextElement();
		sb.append(i + " ");
	}
	return sb.toString();
}

public short
getPayloadSize() {
	return dclass;
}

public short
getExtendedRcode() {
	return (short) (ttl >>> 24);
}

public short
getVersion() {
	return (short) ((ttl >>> 16) & 0xFF);
}

void
rrToWire(DataByteOutputStream dbs, Compression c) throws IOException {
	Enumeration e = options.keys();
	while (e.hasMoreElements()) {
		Integer i = (Integer) e.nextElement();
		short key = i.shortValue();
		dbs.writeShort(key);
		byte [] data = (byte []) options.get(i);
		dbs.writeShort(data.length);
		dbs.write(data);
	}
}

}
