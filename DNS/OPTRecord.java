// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsOPTRecord extends dnsRecord {

short priority;
dnsName target;

public
dnsOPTRecord(dnsName _name, short _dclass, int _ttl) {
	super(_name, dns.OPT, _dclass, _ttl);
}

public
dnsOPTRecord(dnsName _name, short _dclass, int _ttl,
	     int length, CountedDataInputStream in, dnsCompression c)
throws IOException
{
	super(_name, dns.OPT, _dclass, _ttl);
	if (in == null)
		return;
	/* for now, skip the rest */
}

public String
toString() {
	StringBuffer sb = toStringNoData();
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

byte []
rrToWire(dnsCompression c) throws IOException {
	if (target == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	CountedDataOutputStream ds = new CountedDataOutputStream(bs);

	/* probably should dump bytes in here */
	return bs.toByteArray();
}

}
