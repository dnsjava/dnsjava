// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Route Through Record - lists a route preference and intermediate host.
 *
 * @author Brian Wellington
 */

public class RTRecord extends Record {

private int preference;
private Name intermediateHost;

RTRecord() {}

Record
getObject() {
	return new RTRecord();
}

/**
 * Creates an RT Record from the given data
 * @param preference The preference of the route.  Smaller numbers indicate
 * more preferred routes.
 * @param intermediateHost The domain name of the host to use as a router.
 */
public
RTRecord(Name name, int dclass, long ttl, int preference,
	 Name intermediateHost)
{
	super(name, Type.RT, dclass, ttl);

	checkU16("preference", preference);
	this.preference = preference;
	if (!intermediateHost.isAbsolute())
		throw new RelativeNameException(intermediateHost);
	this.intermediateHost = intermediateHost;
}

void
rrFromWire(DNSInput in) throws IOException {
	preference = in.readU16();
	intermediateHost = new Name(in);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	preference = st.getUInt16();
	intermediateHost = st.getName(origin);
}

/** Converts the RT Record to a String */
String
rrToString() {
	StringBuffer sb = new StringBuffer();
	sb.append(preference);
	sb.append(" ");
	sb.append(intermediateHost);
	return sb.toString();
}

/** Gets the preference of the route. */
public int
getPreference() {
	return preference;
}

/** Gets the host to use as a router. */
public Name
getIntermediateHost() {
	return intermediateHost;
}

void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	out.writeU16(preference);
	intermediateHost.toWire(out, null, canonical);
}

}
