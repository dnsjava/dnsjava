// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsSOARecord extends dnsRecord {

dnsName host, admin;
int serial, refresh, retry, expire, minimum;

public
dnsSOARecord(dnsName _name, short _dclass, int _ttl, dnsName _host,
	     dnsName _admin, int _serial, int _refresh, int _retry,
	     int _expire, int _minimum) throws IOException
{
	super(_name, dns.SOA, _dclass, _ttl);
	host = _host;
	admin = _admin;
	serial = _serial;
	refresh = _refresh;
	retry = _retry;
	expire = _expire;
	minimum = _minimum;
}

public
dnsSOARecord(dnsName _name, short _dclass, int _ttl, int length,
	     CountedDataInputStream in, dnsCompression c) throws IOException
{
	super(_name, dns.SOA, _dclass, _ttl);
	if (in == null)
		return;
	host = new dnsName(in, c);
	admin = new dnsName(in, c);
	serial = in.readInt();
	refresh = in.readInt();
	retry = in.readInt();
	expire = in.readInt();
	minimum = in.readInt();
}

public
dnsSOARecord(dnsName _name, short _dclass, int _ttl, MyStringTokenizer st)
throws IOException
{
	super(_name, dns.SOA, _dclass, _ttl);
	host = new dnsName(st.nextToken());
	admin = new dnsName(st.nextToken());
	serial = Integer.parseInt(st.nextToken());
	refresh = Integer.parseInt(st.nextToken());
	retry = Integer.parseInt(st.nextToken());
	expire = Integer.parseInt(st.nextToken());
	minimum = Integer.parseInt(st.nextToken());
}


public String
toString() {
	StringBuffer sb = toStringNoData();
	if (host != null) {
		sb.append(host);
		sb.append(" ");
		sb.append(admin);
		sb.append(" (\n\t\t\t");
		sb.append(serial);
		sb.append("\t; serial\n\t\t\t");
		sb.append(refresh);
		sb.append("\t; refresh\n\t\t\t");
		sb.append(retry);
		sb.append("\t; retry\n\t\t\t");
		sb.append(refresh);
		sb.append("\t; refresh\n\t\t\t");
		sb.append(minimum);
		sb.append(")\t; minimum");
	}
	return sb.toString();
}

byte []
rrToWire() throws IOException {
	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	DataOutputStream ds = new DataOutputStream(bs);

	host.toWire(ds);
	admin.toWire(ds);
	ds.writeInt(serial);
	ds.writeInt(refresh);
	ds.writeInt(retry);
	ds.writeInt(expire);
        ds.writeInt(minimum);

	return bs.toByteArray();
}

}
