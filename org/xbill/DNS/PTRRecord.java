// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Pointer Record  - maps a domain name representing an Internet Address to
 * a hostname.
 *
 * @author Brian Wellington
 */

public class PTRRecord extends NS_CNAME_PTRRecord {

PTRRecord() {}

Record
getObject() {
	return new PTRRecord();
}

/** 
 * Creates a new PTR Record with the given data
 * @param target The name of the machine with this address
 */
public
PTRRecord(Name name, int dclass, long ttl, Name target) {
	super(name, Type.PTR, dclass, ttl, target);
}

}
