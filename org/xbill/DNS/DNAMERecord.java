// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * DNAME Record  - maps a nonterminal alias (subtree) to a different domain
 *
 * @author Brian Wellington
 */

public class DNAMERecord extends NS_CNAME_PTRRecord {

private static DNAMERecord member = new DNAMERecord();

private
DNAMERecord() {}

private
DNAMERecord(Name name, int dclass, int ttl) {
	super(name, Type.DNAME, dclass, ttl);
}

static DNAMERecord
getMember() {
	return member;
}

/**
 * Creates a new DNAMERecord with the given data
 * @param target The name to which the DNAME alias points
 */
public
DNAMERecord(Name name, int dclass, int ttl, Name target) {
	super(name, Type.DNAME, dclass, ttl, target);
}

Record
rrFromWire(Name name, int type, int dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	return rrFromWire(new DNAMERecord(name, dclass, ttl), in);
}

Record
rdataFromString(Name name, int dclass, int ttl, Tokenizer st, Name origin)
throws IOException
{
	return rdataFromString(new DNAMERecord(name, dclass, ttl), st, origin);
}

}
