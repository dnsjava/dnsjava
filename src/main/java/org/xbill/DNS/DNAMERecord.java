// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * DNAME Record  - maps a nonterminal alias (subtree) to a different domain
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc6672">RFC 6672: DNAME Redirection in the DNS</a>
 */
public class DNAMERecord extends SingleNameBase {

private static final long serialVersionUID = 2670767677200844154L;

DNAMERecord() {}

@Override
Record
getObject() {
	return new DNAMERecord();
}

/**
 * Creates a new DNAMERecord with the given data
 * @param alias The name to which the DNAME alias points
 */
public
DNAMERecord(Name name, int dclass, long ttl, Name alias) {
	super(name, Type.DNAME, dclass, ttl, alias, "alias");
}

/**
 * Gets the target of the DNAME Record
 */
public Name
getTarget() {
	return getSingleName();
}

/** Gets the alias specified by the DNAME Record */
public Name
getAlias() {
	return getSingleName();
}

}
