// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsUNKRecord extends dnsRecord {

byte [] data;

public 
dnsUNKRecord(dnsName _name, short _type, short _dclass, int _ttl, int length,
	     CountedDataInputStream in, dnsCompression c) throws IOException
{
	super(_name, _type, _dclass, _ttl);
	wireToData(length, in, c);
}

public 
dnsUNKRecord(dnsName _name, short _type, short _dclass, int _ttl,
	     MyStringTokenizer st) throws IOException
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
wireToData(int length, CountedDataInputStream in, dnsCompression c)
throws IOException
{
	if (in == null)
		return;
	data = new byte[length];
	in.read(data);
}

byte []
rrToWire() {
	return data;
}

}
