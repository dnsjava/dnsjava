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

private String cpu, os;

private
HINFORecord() {}

/**
 * Creates an HINFO Record from the given data
 * @param cpu A string describing the host's CPU
 * @param os A string describing the host's OS
 */
public
HINFORecord(Name _name, short _dclass, int _ttl, String _cpu, String _os)
{
	super(_name, Type.HINFO, _dclass, _ttl);
	cpu = _cpu;
	os = _os;
}

HINFORecord(Name _name, short _dclass, int _ttl, int length,
	    DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.HINFO, _dclass, _ttl);
	if (in == null)
		return;
	cpu = in.readString();
	os = in.readString();
}

HINFORecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	       Name origin)
throws IOException
{
	super(_name, Type.HINFO, _dclass, _ttl);
	cpu = st.nextToken();
	os = st.nextToken();
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
rrToWire(DataByteOutputStream out, Compression c) {
	if (cpu == null || os == null)
		return;

	out.writeString(cpu);
	out.writeString(os);
}

/**
 * Converts to a string
 */
public String
toString() {
	StringBuffer sb = toStringNoData();
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
