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

private short priority, weight, port;
private Name target;

private
SRVRecord() {}

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
SRVRecord(Name _name, short _dclass, int _ttl, int _priority,
	  int _weight, int _port, Name _target)
{
	super(_name, Type.SRV, _dclass, _ttl);
	priority = (short) _priority;
	weight = (short) _priority;
	port = (short) _priority;
	target = _target;
}

SRVRecord(Name _name, short _dclass, int _ttl,
	  int length, DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.SRV, _dclass, _ttl);
	if (in == null)
		return;
	priority = (short) in.readUnsignedShort();
	weight = (short) in.readUnsignedShort();
	port = (short) in.readUnsignedShort();
	target = new Name(in, c);
}

SRVRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	  Name origin)
throws IOException
{
	super(_name, Type.SRV, _dclass, _ttl);
	priority = Short.parseShort(st.nextToken());
	weight = Short.parseShort(st.nextToken());
	port = Short.parseShort(st.nextToken());
	target = new Name(st.nextToken(), origin);
}

/** Converts to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
	if (target != null) {
		sb.append(priority);
		sb.append(" ");
		sb.append(weight);
		sb.append(" ");
		sb.append(port);
		sb.append(" ");
		sb.append(target);
	}
	return sb.toString();
}

/** Returns the priority */
public short
getPriority() {
	return priority;
}

/** Returns the weight */
public short
getWeight() {
	return weight;
}

/** Returns the port that the service runs on */
public short
getPort() {
	return port;
}

/** Returns the host running that the service */
public Name
getTarget() {
	return target;
}

void
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (target == null)
		return;

	out.writeShort(priority);
	out.writeShort(weight);
	out.writeShort(port);
	target.toWire(out, null);
}

void
rrToWireCanonical(DataByteOutputStream out) throws IOException {
	if (target == null)
		return;

	out.writeShort(priority);
	out.writeShort(weight);
	out.writeShort(port);
	target.toWireCanonical(out);
}

}
