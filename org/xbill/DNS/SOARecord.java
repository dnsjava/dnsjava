// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.net.*;
import java.io.*;

public class dnsSOARecord extends dnsRecord {

dnsName host, admin;
int serial, refresh, retry, expire, minimum;

public dnsSOARecord(dnsName rname, short rclass) {
	super(rname, dns.SOA, rclass);
}

public dnsSOARecord(dnsName rname, short rclass, int rttl, dnsName host,
		    dnsName admin, int serial, int refresh, int retry,
		    int expire, int minimum) {
	this(rname, rclass);
	this.rttl = rttl;
	this.host = host;
	this.admin = admin;
	this.serial = serial;
	this.refresh = refresh;
	this.retry = retry;
	this.expire = expire;
	this.minimum = minimum;
	this.rlength = (short) (host.length() + admin.length() + 20);
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	host = new dnsName(in, c);
	admin = new dnsName(in, c);
	serial = in.readInt();
	refresh = in.readInt();
	retry = in.readInt();
	expire = in.readInt();
	minimum = in.readInt();
}

void rrToBytes(DataOutputStream out) throws IOException {
	host.toBytes(out);
	admin.toBytes(out);
	out.writeInt(serial);
	out.writeInt(refresh);
	out.writeInt(retry);
	out.writeInt(expire);
	out.writeInt(minimum);
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	host.toCanonicalBytes(out);
	admin.toCanonicalBytes(out);
	out.writeInt(serial);
	out.writeInt(refresh);
	out.writeInt(retry);
	out.writeInt(expire);
	out.writeInt(minimum);
}

String rrToString() {
	if (rlength == 0)
		return null;
	StringBuffer sb = new StringBuffer();
	sb.append (host.toString());
	sb.append (" ");
	sb.append (admin.toString());
	sb.append (" (");
	sb.append ("\n\t\t\t");
	sb.append (serial);
	sb.append ("\t; serial\n\t\t\t");
	sb.append (refresh);
	sb.append ("\t; refresh\n\t\t\t");
	sb.append (retry);
	sb.append ("\t; retry\n\t\t\t");
	sb.append (expire);
	sb.append ("\t; expire\n\t\t\t");
	sb.append (minimum);
	sb.append (")\t; minimum");
	return sb.toString();
}

}
