import java.net.*;
import java.io.*;
import java.util.*;
import java.text.*;

public class dnsKEYRecord extends dnsRecord {

short flags, protocol, alg;
byte [] key;

dnsKEYRecord(dnsName rname, short rclass) {
	super(rname, dns.KEY, rclass);
}

dnsKEYRecord(dnsName rname, short rclass, int rttl, int flags, int protocol,
	     int alg, byte [] key)
{
	this(rname, rclass);
	this.rttl = rttl;
	this.flags = (short)flags;
	this.protocol = (short)protocol;
	this.alg = (short)alg;
	this.key = key;
	this.rlength = (short) (4 + key.length);
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	flags = in.readShort();
	protocol = (short)in.readUnsignedByte();
	alg = (short)in.readUnsignedByte();
	key = new byte[rlength - 4];
	in.read(key);
}

void rrToBytes(DataOutputStream out) throws IOException {
	out.writeShort(flags);
	out.writeByte((byte)protocol);
	out.writeByte((byte)alg);
	out.write(key, 0, key.length);
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	rrToBytes(out);
}

String rrToString() {
	if (rlength == 0)
		return null;
	StringBuffer sb = new StringBuffer();
	sb.append ("0x");
	sb.append (Integer.toHexString(flags));
	sb.append (" ");
	sb.append (protocol);
	sb.append (" ");
	sb.append (alg);
	sb.append (" (");
	String s = base64.toString(key);
       	for (int i = 0; i < s.length(); i += 64) {
		sb.append ("\n\t");
		if (i + 64 >= s.length()) {
			sb.append(s.substring(i));
			sb.append(" )");
		}
		else {
			sb.append(s.substring(i, i+64));
		} 
	}
	return sb.toString();
}

}
