// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class HINFORecord extends Record {

String cpu, os;

public
HINFORecord(Name _name, short _dclass, int _ttl, String _cpu, String _os)
{
	super(_name, Type.HINFO, _dclass, _ttl);
	cpu = _cpu;
	os = _os;
}

public
HINFORecord(Name _name, short _dclass, int _ttl, int length,
	    CountedDataInputStream in, Compression c)
throws IOException
{
	super(_name, Type.HINFO, _dclass, _ttl);
	if (in == null)
		return;
	cpu = in.readString();
	os = in.readString();
}

public
HINFORecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	       Name origin)
throws IOException
{
	super(_name, Type.HINFO, _dclass, _ttl);
	cpu = st.nextToken();
	os = st.nextToken();
}


public String
getCPU() {
	return cpu;
}

public String
getOS() {
	return os;
}

void
rrToWire(DataByteOutputStream dbs, Compression c) {
	if (cpu == null || os == null)
		return;

	dbs.writeString(cpu);
	dbs.writeString(os);
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	if (cpu != null && os != null) {
		sb.append("\"");
		sb.append(cpu);
		sb.append("\" \"");
		sb.append(os);
		sb.append("\"");
	}
	return sb.toString();
}

}
