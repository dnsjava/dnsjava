import java.net.*;
import java.io.*;
import java.util.*;
import java.text.*;

public class dnsTSIGRecord extends dnsRecord {

dnsName alg;
Date timeSigned;
short fudge;
byte [] signature;
short error;
byte [] other;

public dnsTSIGRecord(dnsName rname, short rclass) {
	super(rname, dns.TSIG, rclass);
}

public dnsTSIGRecord(dnsName rname, short rclass, int rttl, dnsName alg,
		     Date timeSigned, short fudge, byte [] signature,
		     short error, byte other[])
{
	this(rname, rclass);
	this.rttl = rttl;
	this.alg = alg;
	this.timeSigned = timeSigned;
	this.fudge = fudge;
	this.signature = signature;
	this.error = error;
	this.other = other;
	this.rlength = (short) (14 + alg.length() + signature.length +
				other.length);
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	alg = new dnsName(in, c);

	long time = in.readLong();
	fudge = (short) time;
	timeSigned = new Date (1000 * (time >>> 16));

	int sigLen = in.readUnsignedShort();
	signature = new byte[sigLen];
	in.read(signature);

	error = in.readShort();

	int otherLen = in.readUnsignedShort();
	other = new byte[otherLen];
	in.read(other);
}

void rrToBytes(DataOutputStream out) throws IOException {
	alg.toBytes(out);
	long time = (((timeSigned.getTime() / 1000) << 16) + fudge);
	out.writeLong(time);

	out.writeShort((short)signature.length);
	out.write(signature);

	out.writeShort(error);

	out.writeShort((short)other.length);
	out.write(other);
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	alg.toCanonicalBytes(out);
	long time = (((timeSigned.getTime() / 1000) << 16) + fudge);
	out.writeLong(time);

	out.writeShort((short)signature.length);
	out.write(signature);

	out.writeShort(error);

	out.writeShort((short)other.length);
	out.write(other);
}

String rrToString() {
	if (rlength == 0)
		return null;
	StringBuffer sb = new StringBuffer();
	sb.append (alg);
	sb.append (" ");
	sb.append (timeSigned.getTime() / 1000);
	sb.append (" ");
	sb.append (error);
	sb.append (" (\n\t");
	String s = base64.toString(signature);
	for (int i = 0; i < s.length(); i += 64) {
		sb.append ("\n\t");
		if (i + 64 >= s.length()) {
			sb.append(s.substring(i));
			if (other.length > 0) {
				sb.append("\n\t <");
				sb.append(other.length);
				sb.append(" bytes of other data>");
			}
			sb.append(" )");
		}
		else {
			sb.append(s.substring(i, i+64));
		}
	}
	return sb.toString();
}

}
