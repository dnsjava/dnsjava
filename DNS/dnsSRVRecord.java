// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsSRVRecord extends dnsRecord {

short priority, weight, port;
dnsName target;

public
dnsSRVRecord(dnsName _name, short _dclass, int _ttl, int _priority,
	     int _weight, int _port, dnsName _target)
{
	super(_name, dns.SRV, _dclass, _ttl);
	priority = (short) _priority;
	weight = (short) _priority;
	port = (short) _priority;
	target = _target;
}

public
dnsSRVRecord(dnsName _name, short _dclass, int _ttl,
	    int length, CountedDataInputStream in, dnsCompression c)
throws IOException
{
	super(_name, dns.SRV, _dclass, _ttl);
	if (in == null)
		return;
	priority = (short) in.readUnsignedShort();
	weight = (short) in.readUnsignedShort();
	port = (short) in.readUnsignedShort();
	target = new dnsName(in, c);
}

public
dnsSRVRecord(dnsName _name, short _dclass, int _ttl, MyStringTokenizer st)
throws IOException
{
	super(_name, dns.SRV, _dclass, _ttl);
	priority = Short.parseShort(st.nextToken());
	weight = Short.parseShort(st.nextToken());
	port = Short.parseShort(st.nextToken());
	target = new dnsName(st.nextToken());
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	if (target != null) {
		sb.append(priority);
		sb.append(" ");
		sb.append(weight);
		sb.append(" ");
		sb.append(port);
		sb.append(" ");
		sb.append(target);
	}
	return sb.toString();
}

public short
getPriority() {
	return priority;
}

public short
getWeight() {
	return weight;
}

public short
getPort() {
	return port;
}

public dnsName
getTarget() {
	return target;
}

byte []
rrToWire() throws IOException {
	if (target == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	DataOutputStream ds = new DataOutputStream(bs);

	ds.writeShort(priority);
	ds.writeShort(weight);
	ds.writeShort(port);
	target.toWire(ds);
	return bs.toByteArray();
}

}
