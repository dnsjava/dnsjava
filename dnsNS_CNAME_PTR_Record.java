import java.net.*;
import java.io.*;

abstract public class dnsNS_CNAME_MX_Record extends dnsRecord {

dnsName name;

dnsNS_CNAME_MX_Record(dnsName rname, short rtype, short rclass) {
	super(rname, rtype, rclass);
}

dnsNS_CNAME_MX_Record(dnsName rname, short rtype, short rclass, int rttl,
		      dnsName name)
{
	super(rname, rtype, rclass);
	this.rttl = rttl;
	this.name = name;
	this.rlength = name.length();
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	name = new dnsName(in, c);
}

void rrToBytes(DataOutputStream out) throws IOException {
	name.toBytes(out);
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	name.toCanonicalBytes(out);
}

String rrToString() {
	if (rlength == 0)
		return null;
	return name.toString();
}

}
