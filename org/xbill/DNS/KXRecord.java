// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Key Exchange - delegation of authoritu
 *
 * @author Brian Wellington
 */

public class KXRecord extends MX_KXRecord {

private
KXRecord() {}

/**
 * Creates a KX Record from the given data
 * @param preference The preference of this KX.  Records with lower priority
 * are preferred.
 * @param target The host that authority is delegated to
 */
public
KXRecord(Name _name, short _dclass, int _ttl, int _preference, Name _target)
{
	super(_name, Type.KX, _dclass, _ttl, _preference, _target);
}

KXRecord(Name _name, short _dclass, int _ttl,
	    int length, DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.KX, _dclass, _ttl, length, in, c);
}

KXRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, Type.KX, _dclass, _ttl, st, origin);
}

}
