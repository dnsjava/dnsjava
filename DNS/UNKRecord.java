// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class UNKRecord extends Record {

byte [] data;

public 
UNKRecord(Name _name, short _type, short _dclass, int _ttl, int length,
	  CountedDataInputStream in, Compression c) throws IOException
{
	super(_name, _type, _dclass, _ttl);
	if (in == null)
		return;
	data = new byte[length];
	in.read(data);
}

public 
UNKRecord(Name _name, short _type, short _dclass, int _ttl,
	  MyStringTokenizer st, Name origin) throws IOException
{
	super(_name, _type, _dclass, _ttl);
	System.out.println("Unknown type: " + type);
	System.exit(-1);
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	if (data != null)
		sb.append("<unknown format>");
	return sb.toString();
}

void
rrToWire(DataByteOutputStream dbs, Compression c) throws IOException {
	dbs.write(data);
}

}
