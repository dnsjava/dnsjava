// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.text.*;
import java.util.*;

public class dnsSIGRecord extends dnsRecord {

short covered;
byte alg, labels;
int origttl;
Date expire, timeSigned;
short footprint;
dnsName signer;
byte [] signature;

public
dnsSIGRecord(dnsName _name, short _dclass, int _ttl, int _covered, int _alg,
	     int _origttl, Date _expire, Date _timeSigned,
	     int _footprint, dnsName _signer, byte [] _signature)
{
	super(_name, dns.SIG, _dclass, _ttl);
	covered = (short) _covered;
	alg = (byte) _alg;
	labels = name.labels();
	origttl = _origttl;
	expire = _expire;
	timeSigned = _timeSigned;
	footprint = (short) _footprint;
	signer = _signer;
	signature = _signature;
}

public
dnsSIGRecord(dnsName _name, short _dclass, int _ttl,
	     int length, CountedDataInputStream in, dnsCompression c)
throws IOException
{
	super(_name, dns.SIG, _dclass, _ttl);
	if (in == null)
		return;
	int start = in.getPos();
	covered = in.readShort();
	alg = in.readByte();
	labels = in.readByte();
	origttl = in.readInt();
	expire = new Date(1000 * (long)in.readInt());
	timeSigned = new Date(1000 * (long)in.readInt());
	footprint = in.readShort();
	signer = new dnsName(in, c);
	signature = new byte[length - (in.getPos() - start)];
	in.read(signature);
}

public
dnsSIGRecord(dnsName _name, short _dclass, int _ttl, StringTokenizer st)
throws IOException
{
	super(_name, dns.SIG, _dclass, _ttl);
	covered = dns.typeValue(st.nextToken());
	alg = Byte.parseByte(st.nextToken());
	labels = name.labels();
	origttl = Integer.parseInt(st.nextToken());
	expire = parseDate(st.nextToken());
	timeSigned = parseDate(st.nextToken());
	footprint = (short) Integer.parseInt(st.nextToken());
	signer = new dnsName(st.nextToken());
	if (st.hasMoreTokens())
		signature = base64.fromString(st.nextToken());
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	if (signature != null) {
		sb.append (dns.typeString(covered));
		sb.append (" ");
		sb.append (alg);
		sb.append (" ");
		sb.append (origttl);
		sb.append (" (\n\t");
		sb.append (formatDate(expire));
		sb.append (" ");
		sb.append (formatDate(timeSigned));
		sb.append (" ");
		sb.append ((int)footprint & 0xFFFF);
		sb.append (" ");
		sb.append (signer);
		sb.append ("\n");
		String s = base64.toString(signature);
		sb.append (dnsIO.formatBase64String(s, 64, "\t", true));
        }
	return sb.toString();
}

byte []
rrToWire() throws IOException {
	if (signature == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	DataOutputStream ds = new DataOutputStream(bs);

	ds.writeShort(covered);
	ds.writeByte(alg);
	ds.writeByte(labels);
	ds.writeInt(origttl);
	ds.writeInt((int)expire.getTime() / 1000);
	ds.writeInt((int)timeSigned.getTime() / 1000);
	ds.writeShort(footprint);
	signer.toWire(ds);
	ds.write(signature);

	return bs.toByteArray();
}

private String
formatDate(Date d) {
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

private Date
parseDate(String s) {
	Calendar c = new GregorianCalendar(TimeZone.getTimeZone("UTC"));

	int year = Integer.parseInt(s.substring(0, 4));
	int month = Integer.parseInt(s.substring(4, 6));
	int date = Integer.parseInt(s.substring(6, 8));
	int hour = Integer.parseInt(s.substring(8, 10));
	int minute = Integer.parseInt(s.substring(10, 12));
	int second = Integer.parseInt(s.substring(12, 14));
	c.set(year, month, date, hour, minute, second);

	return c.getTime();
}

}
