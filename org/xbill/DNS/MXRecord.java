// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Mail Exchange - specifies where mail to a domain is sent
 *
 * @author Brian Wellington
 */

public class MXRecord extends MX_KXRecord {

private static MXRecord member = new MXRecord();

private
MXRecord() {}

private
MXRecord(Name name, short dclass, int ttl) {
	super(name, Type.MX, dclass, ttl);
}

static MXRecord
getMember() {
	return member;
}

/**
 * Creates an MX Record from the given data
 * @param priority The priority of this MX.  Records with lower priority
 * are preferred.
 * @param target The host that mail is sent to
 */
public
MXRecord(Name name, short dclass, int ttl, int priority, Name target)
{
	super(name, Type.MX, dclass, ttl, priority, target);
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	return rrFromWire(new MXRecord(name, dclass, ttl), in);
}

Record
rdataFromString(Name name, short dclass, int ttl, Tokenizer st, Name origin)
throws IOException
{
	return rdataFromString(new MXRecord(name, dclass, ttl), st, origin);
}

}
