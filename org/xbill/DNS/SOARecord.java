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

private Name host, admin;
private int serial, refresh, retry, expire, minimum;

private
SOARecord() {}

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
SOARecord(Name _name, short _dclass, int _ttl, Name _host, Name _admin,
	  int _serial, int _refresh, int _retry, int _expire, int _minimum)
throws IOException
{
	super(_name, Type.SOA, _dclass, _ttl);
	host = _host;
	admin = _admin;
	serial = _serial;
	refresh = _refresh;
	retry = _retry;
	expire = _expire;
	minimum = _minimum;
}

SOARecord(Name _name, short _dclass, int _ttl, int length,
	  DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.SOA, _dclass, _ttl);
	if (in == null)
		return;
	host = new Name(in, c);
	admin = new Name(in, c);
	serial = in.readInt();
	refresh = in.readInt();
	retry = in.readInt();
	expire = in.readInt();
	minimum = in.readInt();
}

SOARecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	     Name origin)
throws IOException
{
	super(_name, Type.SOA, _dclass, _ttl);
	host = new Name(st.nextToken(), origin);
	admin = new Name(st.nextToken(), origin);
	serial = Integer.parseInt(st.nextToken());
	refresh = TTL.parseTTL(st.nextToken());
	retry = TTL.parseTTL(st.nextToken());
	expire = TTL.parseTTL(st.nextToken());
	minimum = TTL.parseTTL(st.nextToken());
}

/** Convert to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
	if (host != null) {
		sb.append(host);
		sb.append(" ");
		sb.append(admin);
		sb.append(" (\n\t\t\t\t\t");
		sb.append(serial);
		sb.append("\t; serial\n\t\t\t\t\t");
		sb.append(refresh);
		sb.append("\t; refresh\n\t\t\t\t\t");
		sb.append(retry);
		sb.append("\t; retry\n\t\t\t\t\t");
		sb.append(expire);
		sb.append("\t; expire\n\t\t\t\t\t");
		sb.append(minimum);
		sb.append(")\t; minimum");
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (host == null)
		return;

	host.toWire(out, c);
	admin.toWire(out, c);
	out.writeInt(serial);
	out.writeInt(refresh);
	out.writeInt(retry);
	out.writeInt(expire);
        out.writeInt(minimum);
}

void
rrToWireCanonical(DataByteOutputStream out) throws IOException {
	if (host == null)
		return;

	host.toWireCanonical(out);
	admin.toWireCanonical(out);
	out.writeInt(serial);
	out.writeInt(refresh);
	out.writeInt(retry);
	out.writeInt(expire);
        out.writeInt(minimum);
}

}
