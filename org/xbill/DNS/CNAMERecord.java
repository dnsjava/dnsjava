// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * CNAME Record  - maps an alias to its real name
 *
 * @author Brian Wellington
 */

public class CNAMERecord extends NS_CNAME_PTRRecord {

CNAMERecord() {}

Record
getObject() {
	return new CNAMERecord();
}

/**
 * Creates a new CNAMERecord with the given data
 * @param target The name to which the CNAME alias points
 */
public
CNAMERecord(Name name, int dclass, long ttl, Name target) {
	super(name, Type.CNAME, dclass, ttl, target);
}

}
