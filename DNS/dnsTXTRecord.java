import java.util.*;
import java.io.*;

public class dnsTXTRecord extends dnsRecord {

Vector strings;

dnsTXTRecord(dnsName rname, short rclass) {
	super(rname, dns.TXT, rclass);
}

dnsTXTRecord(dnsName rname, short rclass, int ttl, Vector strings) {
	this(rname, rclass);
	this.rttl = rttl;
	this.rlength = 4;
	this.strings = strings;
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	StringBuffer sb = new StringBuffer();
	int count = 0;
	strings = new Vector();

	while (count < rlength) {
		int len = in.readByte();
		byte [] b = new byte[len];
		in.read(b);
		count += (len + 1);
		strings.addElement(new String(b));
	}
}

void rrToBytes(DataOutputStream out) throws IOException {
	Enumeration e = strings.elements();
	while (e.hasMoreElements()) {
		String s = (String) e.nextElement();
		out.write(s.getBytes());
		out.writeByte((byte)0);
	}
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	rrToBytes(out);
}

String rrToString() {
	if (rlength == 0)
		return null;
	StringBuffer sb = new StringBuffer();
	Enumeration e = strings.elements();
	while (e.hasMoreElements()) {
		String s = (String) e.nextElement();
		sb.append("\"");
		sb.append(s);
		sb.append("\" ");
	}
	return sb.toString();
}

}
