// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * AFS Data Base Record - maps a domain name to the name of an AFS cell
 * database server.
 *
 *
 * @author Brian Wellington
 */

public class AFSDBRecord extends Record {

private int subtype;
private Name host;

AFSDBRecord() {}

Record
getObject() {
	return new AFSDBRecord();
}

/**
 * Creates an AFSDB Record from the given data.
 * @param subtype Indicates the type of service provided by the host.
 * @param host The host providing the service.
 */
public
AFSDBRecord(Name name, int dclass, long ttl, int subtype, Name host) {
	super(name, Type.AFSDB, dclass, ttl);

	this.subtype = checkU16("subtype", subtype);
	this.host = checkName("host", host);
}

void
rrFromWire(DNSInput in) throws IOException {
	subtype = in.readU16();
	host = new Name(in);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	subtype = st.getUInt16();
	host = st.getName(origin);
}

String
rrToString() {
	StringBuffer sb = new StringBuffer();
	sb.append(subtype);
	sb.append(" ");
	sb.append(host);
	return sb.toString();
}

/** Gets the subtype indicating the service provided by the host. */
public int
getSubtype() {
	return subtype;
}

/** Gets the host providing service for the domain. */
public Name
getHost() {
	return host;
}

void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	out.writeU16(subtype);
	host.toWire(out, null, canonical);
}

}
