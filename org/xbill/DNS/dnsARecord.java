import java.net.*;
import java.io.*;

public class dnsARecord extends dnsRecord {

InetAddress address;

public dnsARecord(dnsName rname, short rclass) {
	super(rname, dns.A, rclass);
}

public dnsARecord(dnsName rname, short rclass, int ttl, InetAddress address) {
	this(rname, rclass);
	this.rttl = rttl;
	this.rlength = 4;
	this.address = address;
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	int i;
	StringBuffer addressbuf = new StringBuffer();

	if (rlength != 4) {
		System.out.println("Invalid A record - length " + rlength);
	}

	addressbuf.append(in.readUnsignedByte() + ".");
	addressbuf.append(in.readUnsignedByte() + ".");
	addressbuf.append(in.readUnsignedByte() + ".");
	addressbuf.append(in.readUnsignedByte());
	try {
		address = InetAddress.getByName(addressbuf.toString());
	}
	catch (UnknownHostException e) {
		System.out.println("Invalid IP address " + addressbuf);
	}
}

void rrToBytes(DataOutputStream out) throws IOException {
	byte [] b = address.getAddress();
	for (int i=0; i<4; i++)
		out.writeByte(b[i]);
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	rrToBytes(out);
}

String rrToString() {
	if (rlength == 0)
		return null;
	return address.getHostAddress();
}

}
