// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Name Server Record  - contains the name server serving the named zone
 *
 * @author Brian Wellington
 */

public class NSRecord extends NS_CNAME_PTRRecord {

private static NSRecord member = new NSRecord();

private
NSRecord() {}

private
NSRecord(Name name, int dclass, int ttl) {
	super(name, Type.NS, dclass, ttl);
}

static NSRecord
getMember() {
	return member;
}

/** 
 * Creates a new NS Record with the given data
 * @param target The name server for the given domain
 */
public
NSRecord(Name name, int dclass, int ttl, Name target) {
	super(name, Type.NS, dclass, ttl, target);
}

Record
rrFromWire(Name name, int type, int dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	return rrFromWire(new NSRecord(name, dclass, ttl), in);
}

Record
rdataFromString(Name name, int dclass, int ttl, Tokenizer st, Name origin)
throws IOException
{
	return rdataFromString(new NSRecord(name, dclass, ttl), st, origin);
}

public Name
getAdditionalName() {
	return target;
}

}
