import java.net.*;
import java.io.*;

public class dnsMXRecord extends dnsRecord {

short priority;
dnsName name;

dnsMXRecord(dnsName rname, short rclass) {
	super(rname, dns.MX, rclass);
}

dnsMXRecord(dnsName rname, short rclass, int rttl, int priority, dnsName name) {
	this(rname, rclass);
	this.rttl = rttl;
	this.priority = (short)priority;
	this.name = name;
	this.rlength = (short)(2 + name.length());
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	priority = (short)in.readUnsignedShort();
	name = new dnsName(in, c);
}

void rrToBytes(DataOutputStream out) throws IOException {
	out.writeShort(priority);
	name.toBytes(out);
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	out.writeShort(priority);
	name.toCanonicalBytes(out);
}

String rrToString() {
	if (rlength == 0)
		return null;
	StringBuffer sb = new StringBuffer();
	sb.append(priority);
	sb.append(" ");
	sb.append(name);
	return sb.toString();
}

}
