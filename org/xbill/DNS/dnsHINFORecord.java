// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsHINFORecord extends dnsRecord {

String cpu, os;

public
dnsHINFORecord(dnsName _name, short _dclass, int _ttl, String _cpu, String _os)
{
	super(_name, dns.HINFO, _dclass, _ttl);
	cpu = _cpu;
	os = _os;
}

public
dnsHINFORecord(dnsName _name, short _dclass, int _ttl, int length,
	       CountedDataInputStream in, dnsCompression c)
throws IOException
{
	super(_name, dns.HINFO, _dclass, _ttl);
	if (in == null)
		return;
	cpu = in.readString();
	os = in.readString();
}

public
dnsHINFORecord(dnsName _name, short _dclass, int _ttl, MyStringTokenizer st,
	       dnsName origin)
throws IOException
{
	super(_name, dns.HINFO, _dclass, _ttl);
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

byte[] rrToWire(dnsCompression c) throws IOException {
	if (cpu == null || os == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	CountedDataOutputStream ds = new CountedDataOutputStream(bs);

	ds.writeString(cpu);
	ds.writeString(os);

	return bs.toByteArray();
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
