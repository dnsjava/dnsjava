// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Start of Authority - describes properties of a zone.
 *
 * @author Brian Wellington
 */

public class SOARecord extends Record {

private static SOARecord member = new SOARecord();

private Name host, admin;
private int serial, refresh, retry, expire, minimum;

private
SOARecord() {}

private
SOARecord(Name name, short dclass, int ttl) {
	super(name, Type.SOA, dclass, ttl);
}

static SOARecord
getMember() {
	return member;
}

/**
 * Creates an SOA Record from the given data
 * @param host The primary nameserver for the zone
 * @param admin The zone administrator's address
 * @param serial The zone's serial number
 * @param refresh The amount of time until a secondary checks for a new serial
 * number
 * @param retry The amount of time between a secondary's checks for a new
 * serial number
 * @param expire The amount of time until a secondary expires a zone
 * @param minimum The minimum TTL for records in the zone
*/
public
SOARecord(Name name, short dclass, int ttl, Name host, Name admin,
	  int serial, int refresh, int retry, int expire, int minimum)
{
	this(name, dclass, ttl);
	this.host = host;
	this.admin = admin;
	this.serial = serial;
	this.refresh = refresh;
	this.retry = retry;
	this.expire = expire;
	this.minimum = minimum;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	SOARecord rec = new SOARecord(name, dclass, ttl);
	if (in == null)
		return rec;
	rec.host = new Name(in);
	rec.admin = new Name(in);
	rec.serial = in.readInt();
	rec.refresh = in.readInt();
	rec.retry = in.readInt();
	rec.expire = in.readInt();
	rec.minimum = in.readInt();
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	SOARecord rec = new SOARecord(name, dclass, ttl);
	rec.host = Name.fromString(nextString(st), origin);
	rec.host.checkAbsolute("read an SOA record");
	rec.admin = Name.fromString(nextString(st), origin);
	rec.admin.checkAbsolute("read an SOA record");
	long tserial = Long.parseLong(nextString(st));
	if (tserial > 0xFFFFFFFFL)
		throw new TextParseException("Invalid serial number");
	rec.serial = (int) tserial;
	rec.refresh = TTL.parseTTL(nextString(st));
	rec.retry = TTL.parseTTL(nextString(st));
	rec.expire = TTL.parseTTL(nextString(st));
	rec.minimum = TTL.parseTTL(nextString(st));
	return rec;
}

/** Convert to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (host != null) {
		sb.append(host);
		sb.append(" ");
		sb.append(admin);
		if (Options.check("multiline")) {
			sb.append(" (\n\t\t\t\t\t");
			sb.append(serial & 0xFFFFFFFFL);
			sb.append("\t; serial\n\t\t\t\t\t");
			sb.append(refresh);
			sb.append("\t; refresh\n\t\t\t\t\t");
			sb.append(retry);
			sb.append("\t; retry\n\t\t\t\t\t");
			sb.append(expire);
			sb.append("\t; expire\n\t\t\t\t\t");
			sb.append(minimum);
			sb.append(" )\t; minimum");
		} else {
			sb.append(serial & 0xFFFFFFFFL);
			sb.append(" ");
			sb.append(refresh);
			sb.append(" ");
			sb.append(retry);
			sb.append(" ");
			sb.append(expire);
			sb.append(" ");
			sb.append(minimum);
		}
	}
	return sb.toString();
}

/** Returns the primary nameserver */
public Name
getHost() {  
	return host;
}       

/** Returns the zone administrator's address */
public Name
getAdmin() {  
	return admin;
}       

/** Returns the zone's serial number */
public int
getSerial() {  
	return serial;
}       

/** Returns the zone refresh interval */
public int
getRefresh() {  
	return refresh;
}       

/** Returns the zone retry interval */
public int
getRetry() {  
	return retry;
}       

/** Returns the time until a secondary expires a zone */
public int
getExpire() {  
	return expire;
}       

/** Returns the minimum TTL for records in the zone */
public int
getMinimum() {  
	return minimum;
}       

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (host == null)
		return;

	host.toWire(out, c, canonical);
	admin.toWire(out, c, canonical);
	out.writeInt(serial);
	out.writeInt(refresh);
	out.writeInt(retry);
	out.writeInt(expire);
	out.writeInt(minimum);
}

}
