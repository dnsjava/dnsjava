// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Server Selection Record  - finds hosts running services in a domain.  An
 * SRV record will normally be named <service>.<protocol>.domain - an
 * example would be http.tcp.example.com (if HTTP used SRV records)
 *
 * @author Brian Wellington
 */

public class SRVRecord extends Record {

private int priority, weight, port;
private Name target;

SRVRecord() {}

Record
getObject() {
	return new SRVRecord();
}

/**
 * Creates an SRV Record from the given data
 * @param priority The priority of this SRV.  Records with lower priority
 * are preferred.
 * @param weight The weight, used to select between records at the same
 * priority.
 * @param port The TCP/UDP port that the service uses
 * @param target The host running the service
 */
public
SRVRecord(Name name, int dclass, long ttl, int priority,
	  int weight, int port, Name target)
{
	super(name, Type.SRV, dclass, ttl);
	checkU16("priority", priority);
	checkU16("weight", weight);
	checkU16("port", port);
	this.priority = priority;
	this.weight = weight;
	this.port = port;
	if (!target.isAbsolute())
		throw new RelativeNameException(target);
	this.target = target;
}

void
rrFromWire(DNSInput in) throws IOException {
	priority = in.readU16();
	weight = in.readU16();
	port = in.readU16();
	target = new Name(in);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	priority = st.getUInt16();
	weight = st.getUInt16();
	port = st.getUInt16();
	target = st.getName(origin);
}

/** Converts rdata to a String */
String
rrToString() {
	StringBuffer sb = new StringBuffer();
	sb.append(priority + " ");
	sb.append(weight + " ");
	sb.append(port + " ");
	sb.append(target);
	return sb.toString();
}

/** Returns the priority */
public int
getPriority() {
	return priority;
}

/** Returns the weight */
public int
getWeight() {
	return weight;
}

/** Returns the port that the service runs on */
public int
getPort() {
	return port;
}

/** Returns the host running that the service */
public Name
getTarget() {
	return target;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (target == null)
		return;

	out.writeShort(priority);
	out.writeShort(weight);
	out.writeShort(port);
	target.toWire(out, null, canonical);
}

public Name
getAdditionalName() {
	return target;
}

}
