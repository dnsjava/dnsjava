// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * A class implementing Records of unknown and/or unimplemented types.  This
 * class can only be initialized using static Record initializers.
 *
 * @author Brian Wellington
 */

public class UNKRecord extends Record {

private byte [] data;

private
UNKRecord() {}

UNKRecord(Name _name, short _type, short _dclass, int _ttl, int length,
	  DataByteInputStream in, Compression c) throws IOException
{
	super(_name, _type, _dclass, _ttl);
	if (in == null)
		return;
	if (length > 0) {
		data = new byte[length];
		in.read(data);
	}
	else
		data = null;
}

UNKRecord(Name _name, short _type, short _dclass, int _ttl,
	  MyStringTokenizer st, Name origin) throws IOException
{
	super(_name, _type, _dclass, _ttl);
	throw new IOException("Invalid unknown RR encoding");
}

/** Converts this Record to the String "unknown format" */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (data != null) {
		sb.append("\\# ");
		sb.append(data.length);
		sb.append(" ");
		sb.append(base16.toString(data));
	}
	return sb.toString();
}

void
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (data != null)
		out.write(data);
}

}
