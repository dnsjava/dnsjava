// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Host Information - describes the CPU and OS of a host
 *
 * @author Brian Wellington
 */

public class HINFORecord extends Record {

private static HINFORecord member = new HINFORecord();

private String cpu, os;

private
HINFORecord() {}

private
HINFORecord(Name name, short dclass, int ttl) {
	super(name, Type.HINFO, dclass, ttl);
}

static HINFORecord
getMember() {
	return member;
}

/**
 * Creates an HINFO Record from the given data
 * @param cpu A string describing the host's CPU
 * @param os A string describing the host's OS
 */
public
HINFORecord(Name name, short dclass, int ttl, String cpu, String os) {
	this(name, dclass, ttl);
	this.cpu = cpu;
	this.os = os;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	HINFORecord rec = new HINFORecord(name, dclass, ttl);
	if (in == null)
		return rec;
	rec.cpu = in.readString();
	rec.os = in.readString();
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	HINFORecord rec = new HINFORecord(name, dclass, ttl);
	rec.cpu = nextString(st);
	rec.os = nextString(st);
	return rec;
}

/**
 * Returns the host's CPU
 */
public String
getCPU() {
	return cpu;
}

/**
 * Returns the host's OS
 */
public String
getOS() {
	return os;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (cpu == null || os == null)
		return;

	out.writeString(cpu);
	out.writeString(os);
}

/**
 * Converts to a string
 */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (cpu != null && os != null) {
		sb.append("\"");
		sb.append(cpu);
		sb.append("\" \"");
		sb.append(os);
		sb.append("\"");
	}
	return sb.toString();
}

}
