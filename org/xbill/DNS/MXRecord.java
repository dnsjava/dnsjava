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

private
MXRecord() {}

/**
 * Creates an MX Record from the given data
 * @param priority The priority of this MX.  Records with lower priority
 * are preferred.
 * @param target The host that mail is sent to
 */
public
MXRecord(Name _name, short _dclass, int _ttl, int _priority, Name _target)
{
	super(_name, Type.MX, _dclass, _ttl, _priority, _target);
}

MXRecord(Name _name, short _dclass, int _ttl,
	    int length, DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.MX, _dclass, _ttl, length, in, c);
}

MXRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, Type.MX, _dclass, _ttl, st, origin);
}

}
