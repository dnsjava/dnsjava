// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Key Exchange - delegation of authority
 *
 * @author Brian Wellington
 */

public class KXRecord extends MX_KXRecord {

private static KXRecord member = new KXRecord();

private
KXRecord() {}

private
KXRecord(Name name, int dclass, int ttl) {
	super(name, Type.KX, dclass, ttl);
}

static KXRecord
getMember() {
	return member;
}

/**
 * Creates a KX Record from the given data
 * @param preference The preference of this KX.  Records with lower priority
 * are preferred.
 * @param target The host that authority is delegated to
 */
public
KXRecord(Name name, int dclass, int ttl, int preference, Name target) {
	super(name, Type.KX, dclass, ttl, preference, target);
}

Record
rrFromWire(Name name, int type, int dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	return rrFromWire(new KXRecord(name, dclass, ttl), in);
}

Record
rdataFromString(Name name, int dclass, int ttl, Tokenizer st, Name origin)
throws IOException
{
	return rdataFromString(new KXRecord(name, dclass, ttl), st, origin);
}

}
