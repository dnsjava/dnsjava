// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * DNAME Record  - maps a nonterminal alias (subtree) to a different domain
 *
 * @author Brian Wellington
 */

public class DNAMERecord extends NS_CNAME_PTRRecord {

DNAMERecord() {}

Record
getObject() {
	return new DNAMERecord();
}

/**
 * Creates a new DNAMERecord with the given data
 * @param target The name to which the DNAME alias points
 */
public
DNAMERecord(Name name, int dclass, long ttl, Name target) {
	super(name, Type.DNAME, dclass, ttl, target);
}

}
