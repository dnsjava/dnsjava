import java.net.*;
import java.io.*;
import java.util.*;
import java.text.*;

public class dnsSIGRecord extends dnsRecord {

short typeCovered;
byte alg;
byte labels;
int origTTL;
Date expire, timeSigned;
short footprint;
dnsName signer;
byte [] signature;

public dnsSIGRecord(dnsName rname, short rclass) {
	super(rname, dns.SIG, rclass);
}

public dnsSIGRecord(dnsName rname, short rclass, int rttl, short typeCovered,
		    byte alg, byte labels, int origTTL, Date expire,
		    Date timeSigned, short footprint, dnsName signer,
		    byte [] signature)
{
	this(rname, rclass);
	this.rttl = rttl;
	this.typeCovered = typeCovered;
	this.alg = alg;
	this.labels = labels;
	this.origTTL = origTTL;
	this.expire = expire;
	this.timeSigned = timeSigned;
	this.footprint = footprint;
	this.signer = signer;
	this.signature = signature;
	this.rlength = (short) (18 + signer.length() + signature.length);
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	typeCovered = (short) in.readUnsignedShort();
	alg = (byte) in.readUnsignedByte();
	labels = (byte) in.readUnsignedByte();
	origTTL = in.readInt();
	expire = new Date (1000 * (long)in.readInt());
	timeSigned = new Date (1000 * (long)in.readInt());
	footprint = (short) in.readUnsignedShort();
	int pos = in.pos();
	signer = new dnsName(in, c);
	signature = new byte[rlength - 18 - (in.pos() - pos)];
	in.read(signature);
}

void rrToBytes(DataOutputStream out) throws IOException {
	out.writeShort(typeCovered);
	out.writeByte(alg);
	out.writeByte(labels);
	out.writeInt(origTTL);
	out.writeInt((int)(expire.getTime() / 1000));
	out.writeInt((int)(timeSigned.getTime() / 1000));
	out.writeShort(footprint);
	signer.toBytes(out);
	out.write(signature, 0, signature.length);
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	out.writeShort(typeCovered);
	out.writeByte(alg);
	out.writeByte(labels);
	out.writeInt(origTTL);
	out.writeInt((int)(expire.getTime() / 1000));
	out.writeInt((int)(timeSigned.getTime() / 1000));
	out.writeShort(footprint);
	signer.toCanonicalBytes(out);
	out.write(signature, 0, signature.length);
}

String rrToString() {
	if (rlength == 0)
		return null;
	StringBuffer sb = new StringBuffer();
	sb.append (dns.typeString(typeCovered));
	sb.append ("\t");
	sb.append (alg);
	sb.append (" ");
	sb.append (origTTL);
	sb.append (" (\n\t");
	sb.append (formatDate(expire));
        sb.append (" ");
	sb.append (formatDate(timeSigned));
	sb.append (" ");
	sb.append (footprint);
	sb.append (" ");
	sb.append (signer);
	String s = base64.toString(signature);
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

String formatDate(Date d) {
	Calendar c = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
	StringBuffer sb = new StringBuffer();
	NumberFormat w4 = new DecimalFormat();
	w4.setMinimumIntegerDigits(4);
	w4.setGroupingUsed(false);
	NumberFormat w2 = new DecimalFormat();
	w2.setMinimumIntegerDigits(2);

	c.setTime(d);
	sb.append(w4.format(c.get(c.YEAR)));
	sb.append(w2.format(c.get(c.MONTH)+1));
	sb.append(w2.format(c.get(c.DAY_OF_MONTH)));
	sb.append(w2.format(c.get(c.HOUR_OF_DAY)));
	sb.append(w2.format(c.get(c.MINUTE)));
	sb.append(w2.format(c.get(c.SECOND)));
	return sb.toString();
}

}
