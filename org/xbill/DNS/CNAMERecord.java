// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * CNAME Record  - maps an alias to its real name
 *
 * @author Brian Wellington
 */

public class CNAMERecord extends NS_CNAME_PTRRecord {

private static CNAMERecord member = new CNAMERecord();

private
CNAMERecord() {}

private
CNAMERecord(Name name, short dclass, int ttl) {
	super(name, Type.CNAME, dclass, ttl);
}

static CNAMERecord
getMember() {
	return member;
}

/**
 * Creates a new CNAMERecord with the given data
 * @param target The name to which the CNAME alias points
 */
public
CNAMERecord(Name _name, short _dclass, int _ttl, Name _target)
throws IOException
{
        super(_name, Type.CNAME, _dclass, _ttl, _target);
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	return rrFromWire(new CNAMERecord(name, dclass, ttl), in);
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
                Name origin)
throws TextParseException
{
        return rdataFromString(new CNAMERecord(name, dclass, ttl), st, origin);
}

}
