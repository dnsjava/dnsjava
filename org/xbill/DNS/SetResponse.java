// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * The Response from a query to Cache.lookupRecords() or Zone.findRecords()
 * @see Cache
 * @see Zone
 *
 * @author Brian Wellington
 */

public class SetResponse {

/**
 * The Cache contains no information about the requested name/type
 */
static final byte UNKNOWN	= 0;

/**
 * The Zone does not contain the requested name, or the Cache has
 * determined that the name does not exist.
 */
static final byte NXDOMAIN	= 1;

/**
 * The Zone contains the name, but no data of the requested type,
 * or the Cache has determined that the name exists and has no data
 * of the requested type.
 */
static final byte NXRRSET	= 2;

/**
 * A delegation enclosing the requested name was found.
 */
static final byte DELEGATION	= 3;

/**
 * The Cache/Zone found a CNAME when looking for the name.
 * @see CNAMERecord
 */
static final byte CNAME		= 4;

/**
 * The Cache/Zone found a DNAME when looking for the name.
 * @see CNAMERecord
 */
static final byte DNAME		= 5;

/**
 * The Cache/Zone has successfully answered the question for the
 * requested name/type/class.
 */
static final byte SUCCESSFUL	= 6;

private byte type;
private Object data;

private
SetResponse() {}

SetResponse(byte _type, Object _data) {
	type = _type;
	data = _data;
}

SetResponse(byte _type) {
	this(_type, null);
}

/** Changes the value of a SetResponse */
void
set(byte _type, Object _data) {
	type = _type;
	data = _data;
}

void
addRRset(RRset rrset) {
	if (data == null)
		data = new Vector();
	Vector v = (Vector) data;
	v.addElement(rrset);
}

void
addNS(RRset nsset) {
	data = nsset;
}

void
addCNAME(CNAMERecord cname) {
	data = cname;
}

void
addDNAME(DNAMERecord dname) {
	data = dname;
}

/** Is the answer to the query unknown? */
public boolean
isUnknown() {
	return (type == UNKNOWN);
}

/** Is the answer to the query that the name does not exist? */
public boolean
isNXDOMAIN() {
	return (type == NXDOMAIN);
}

/** Is the answer to the query that the name exists, but the type does not? */
public boolean
isNXRRSET() {
	return (type == NXRRSET);
}

/** Is the result of the lookup that the name is below a delegation? */
public boolean
isDelegation() {
	return (type == DELEGATION);
}

/** Is the result of the lookup a dangling CNAME? */
public boolean
isCNAME() {
	return (type == CNAME);
}

/** Is the result of the lookup a dangling DNAME? */
public boolean
isDNAME() {
	return (type == DNAME);
}

/** Was the query successful? */
public boolean
isSuccessful() {
	return (type == SUCCESSFUL);
}

/** If the query was successful, return the answers */
public RRset []
answers() {
	if (type != SUCCESSFUL)
		return null;
	Vector v = (Vector) data;
	RRset [] rrsets = new RRset[v.size()];
	for (int i = 0; i < rrsets.length; i++)
		rrsets[i] = (RRset) v.elementAt(i);
	return rrsets;
}

/**
 * If the query was partially successful, return the last CNAME/DNAME found in
 * the lookup process.
 */
public CNAMERecord
partial() {
	if (type != SUCCESSFUL)
		return null;
	return (CNAMERecord) data;
}

/**
 * If the query encountered CNAME point, return it.
 */
public CNAMERecord
getCNAME() {
	return (CNAMERecord) data;
}

/**
 * If the query encountered CNAME point, return it.
 */
public DNAMERecord
getDNAME() {
	return (DNAMERecord) data;
}

/**
 * If the query hit a delegation point, return the NS set.
 */
public RRset
getNS() {
	return (RRset) data;
}

/** Prints the value of the CacheResponse */
public String
toString() {
	switch (type) {
		case UNKNOWN:		return "unknown";
		case NXDOMAIN:		return "NXDOMAIN";
		case NXRRSET:		return "NXRRSET";
		case DELEGATION:	return "delegation: " + data;
		case CNAME:		return "CNAME: " + data;
		case DNAME:		return "DNAME: " + data;
		case SUCCESSFUL:	return "successful";
		default:	return null;
	}
}

}
