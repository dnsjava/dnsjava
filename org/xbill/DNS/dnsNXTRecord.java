import java.net.*;
import java.io.*;

public class dnsNXTRecord extends dnsRecord {

dnsName nextName;
boolean [] typeBitmap;

public dnsNXTRecord(dnsName rname, short rclass) {
	super(rname, dns.NXT, rclass);
}

public dnsNXTRecord(dnsName rname, short rclass, dnsName nextName,
		    boolean [] typeBitmap)
{
	this(rname, rclass);
	this.rttl = rttl;
	this.nextName = nextName;
	this.typeBitmap = typeBitmap;
	this.rlength = (short) (nextName.length() + (typeBitmap.length + 7)/8);
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	int pos = in.pos();
	nextName = new dnsName(in, c);
	int bitmapLength = rlength - (in.pos() - pos);
	typeBitmap = new boolean[bitmapLength * 8];
	for (int i = 0; i < bitmapLength; i++) {
		int t = in.readUnsignedByte();
		for (int j = 0; j < 8; j++)
			typeBitmap[i * 8 + j] = ((t & (1 << (7 - j))) != 0);
	}
}

void rrToBytes(DataOutputStream out) throws IOException {
	nextName.toBytes(out);
	for (int i = 0, t = 0; i < typeBitmap.length; i++) {
		t |= (typeBitmap[i] ? (1 << (7 - i % 8)) : 0);
		if (i % 8 == 7 || i == typeBitmap.length - 1) {
			out.writeByte(t);
			t = 0;
		}
	}
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	nextName.toCanonicalBytes(out);
	for (int i = 0, t = 0; i < typeBitmap.length; i++) {
		t |= (typeBitmap[i] ? (1 << (7 - i % 8)) : 0);
		if (i % 8 == 7 || i == typeBitmap.length - 1) {
			out.writeByte(t);
			t = 0;
		}
	}
}

String rrToString() {
	if (rlength == 0)
		return null;
	StringBuffer sb = new StringBuffer();
	sb.append(nextName.toString());
	sb.append(" ");
	for (int i = 0; i < typeBitmap.length; i++)
		if (typeBitmap[i]) {
			sb.append(dns.typeString(i));
			sb.append(" ");
		}
	return sb.toString();
}

}
