// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Name Server Record  - contains the name server serving the named zone
 *
 * @author Brian Wellington
 */

public class NSRecord extends NS_CNAME_PTRRecord {

NSRecord() {}

Record
getObject() {
	return new NSRecord();
}

/** 
 * Creates a new NS Record with the given data
 * @param target The name server for the given domain
 */
public
NSRecord(Name name, int dclass, long ttl, Name target) {
	super(name, Type.NS, dclass, ttl, target);
}

public Name
getAdditionalName() {
	return target;
}

}
