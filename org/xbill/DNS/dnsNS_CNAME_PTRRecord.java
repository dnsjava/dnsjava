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
	if (in == null)
		return;
	target = new dnsName(in, c);
}

public
dnsNS_CNAME_PTRRecord(dnsName _name, short _type, short _dclass, int _ttl,
		      MyStringTokenizer st, dnsName origin)
throws IOException
{
        super(_name, _type, _dclass, _ttl);
        target = new dnsName(st.nextToken(), origin);
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

byte []
rrToWire(dnsCompression c) throws IOException {
	if (target == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	CountedDataOutputStream ds = new CountedDataOutputStream(bs);

	target.toWire(ds, c);
	return bs.toByteArray();
}

}
