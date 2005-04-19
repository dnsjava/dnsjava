// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Mail Destination Record  - specifies a mail agent which delivers mail
 * for a domain (obsolete)
 *
 * @author Brian Wellington
 */

public class MDRecord extends SingleNameBase {

MDRecord() {}

Record
getObject() {
	return new MDRecord();
}

/** 
 * Creates a new MD Record with the given data
 * @param mailAgent The mail agent that delivers mail for the domain.
 */
public
MDRecord(Name name, int dclass, long ttl, Name mailAgent) {
	super(name, Type.MD, dclass, ttl, mailAgent, "mail agent");
}

/** Gets the mail agent for the domain */
public Name
getMailAgent() {
	return getSingleName();
}

public Name
getAdditionalName() {
	return getSingleName();
}

}
