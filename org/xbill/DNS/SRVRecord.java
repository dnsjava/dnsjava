// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Server Selection Record  - finds hosts running services in a domain.  An
 * SRV record will normally be named <service>.<protocol>.domain - an
 * example would be http.tcp.example.com (if HTTP used SRV records)
 *
 * @author Brian Wellington
 */

public class SRVRecord extends Record {

private static SRVRecord member = new SRVRecord();

private int priority, weight, port;
private Name target;

private
SRVRecord() {}

private
SRVRecord(Name name, short dclass, int ttl) {
	super(name, Type.SRV, dclass, ttl);
}

static SRVRecord
getMember() {
	return member;
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
SRVRecord(Name name, short dclass, int ttl, int priority,
	  int weight, int port, Name target)
{
	this(name, dclass, ttl);
	if (priority < 0 || priority > 0xFFFF)
		throw new IllegalArgumentException("priority is out of range");
	if (weight < 0 || weight > 0xFFFF)
		throw new IllegalArgumentException("weight is out of range");
	if (port < 0 || port > 0xFFFF)
		throw new IllegalArgumentException("port is out of range");
	this.priority = priority;
	this.weight = weight;
	this.port = port;
	if (!target.isAbsolute())
		throw new RelativeNameException(target);
	this.target = target;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	SRVRecord rec = new SRVRecord(name, dclass, ttl);
	if (in == null)
		return rec;
	rec.priority = in.readUnsignedShort();
	rec.weight = in.readUnsignedShort();
	rec.port = in.readUnsignedShort();
	rec.target = new Name(in);
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, Tokenizer st, Name origin)
throws IOException
{
	SRVRecord rec = new SRVRecord(name, dclass, ttl);
	rec.priority = st.getUInt16();
	rec.weight = st.getUInt16();
	rec.port = st.getUInt16();
	rec.target = st.getName(origin);
	return rec;
}

/** Converts rdata to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (target != null) {
		sb.append(priority + " ");
		sb.append(weight + " ");
		sb.append(port + " ");
		sb.append(target);
	}
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
