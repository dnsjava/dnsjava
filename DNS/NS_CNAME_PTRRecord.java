// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsNS_CNAME_PTRRecord extends dnsRecord {

dnsName target;

public
dnsNS_CNAME_PTRRecord(dnsName _name, short _type, short _dclass, int _ttl,
		      dnsName _target)
{
	super(_name, _type, _dclass, _ttl);
	target = _target;
}

public
dnsNS_CNAME_PTRRecord(dnsName _name, short _type, short _dclass, int _ttl,
		      int length, CountedDataInputStream in, dnsCompression c)
throws IOException
{
	super(_name, _type, _dclass, _ttl);
	wireToData(in, c);
}

public
dnsNS_CNAME_PTRRecord(dnsName _name, short _type, short _dclass, int _ttl,
		      StringTokenizer st)
throws IOException
{
        super(_name, _type, _dclass, _ttl);
        target = new dnsName(st.nextToken());
}


public String
toString() {
	StringBuffer sb = toStringNoData();
	if (target != null)
		sb.append(target);
	return sb.toString();
}

public dnsName
getTarget() {
	return target;
}

void
wireToData(CountedDataInputStream in, dnsCompression c) throws IOException {
	if (in == null)
		return;
	target = new dnsName(in, c);
}

byte []
rrToWire() throws IOException {
	if (target == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	DataOutputStream ds = new DataOutputStream(bs);

	target.toWire(ds);
	return bs.toByteArray();
}

}
