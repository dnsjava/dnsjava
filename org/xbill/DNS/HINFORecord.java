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

private byte [] cpu, os;

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
 * @throws IllegalArgumentException One of the strings has invalid escapes
 */
public
HINFORecord(Name name, short dclass, int ttl, String cpu, String os) {
	this(name, dclass, ttl);
	try {
		this.cpu = byteArrayFromString(cpu);
		this.os = byteArrayFromString(os);
	}
	catch (TextParseException e) {
		throw new IllegalArgumentException(e.getMessage());
	}
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	HINFORecord rec = new HINFORecord(name, dclass, ttl);
	if (in == null)
		return rec;
	rec.cpu = in.readStringIntoArray();
	rec.os = in.readStringIntoArray();
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, Tokenizer st, Name origin)
throws IOException
{
	HINFORecord rec = new HINFORecord(name, dclass, ttl);
	try {
		rec.cpu = byteArrayFromString(st.getString());
		rec.os = byteArrayFromString(st.getString());
	}
	catch (TextParseException e) {
		throw st.exception(e.getMessage());
	}
	return rec;
}

/**
 * Returns the host's CPU
 */
public String
getCPU() {
	return byteArrayToString(cpu, false);
}

/**
 * Returns the host's OS
 */
public String
getOS() {
	return byteArrayToString(os, false);
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (cpu == null || os == null)
		return;

	out.writeArray(cpu, true);
	out.writeArray(os, true);
}

/**
 * Converts to a string
 */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (cpu != null && os != null) {
		sb.append(byteArrayToString(cpu, true));
		sb.append(" ");
		sb.append(byteArrayToString(os, true));
	}
	return sb.toString();
}

}
