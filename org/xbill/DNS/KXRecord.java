// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Key Exchange - delegation of authority
 *
 * @author Brian Wellington
 */

public class KXRecord extends MX_KXRecord {

KXRecord() {}

Record
getObject() {
	return new KXRecord();
}

/**
 * Creates a KX Record from the given data
 * @param preference The preference of this KX.  Records with lower priority
 * are preferred.
 * @param target The host that authority is delegated to
 */
public
KXRecord(Name name, int dclass, long ttl, int preference, Name target) {
	super(name, Type.KX, dclass, ttl, preference, target);
}

}
