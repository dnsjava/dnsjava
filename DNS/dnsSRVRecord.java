import java.net.*;
import java.io.*;

public class dnsSRVRecord extends dnsRecord {

int priority, weight, port;
dnsName name;

public dnsSRVRecord(dnsName rname, short rclass) {
	super(rname, dns.SRV, rclass);
}

public dnsSRVRecord(dnsName rname, short rclass, int rttl, int priority,
		    int weight, int port, dnsName name)
{
	this(rname, rclass);
	this.rttl = rttl;
	this.priority = priority;
	this.weight = weight;
	this.port = port;
	this.name = name;
	this.rlength = (short)(6 + name.length());
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	priority = in.readUnsignedShort();
	weight = in.readUnsignedShort();
	port = in.readUnsignedShort();
	name = new dnsName(in, c);
}

void rrToBytes(DataOutputStream out) throws IOException {
	out.writeShort(priority);
	out.writeShort(weight);
	out.writeShort(port);
	name.toBytes(out);
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	out.writeShort(priority);
	out.writeShort(weight);
	out.writeShort(port);
	name.toCanonicalBytes(out);
}

String rrToString() {
	if (rlength == 0)
		return null;
	StringBuffer sb = new StringBuffer();
	sb.append(priority);
	sb.append(" ");
	sb.append(weight);
	sb.append(" ");
	sb.append(port);
	sb.append(" ");
	sb.append(name);
	return sb.toString();
}

}
