// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import DNS.utils.*;

/**
 * The Response from a query to Cache.lookupRecords().
 * @see Cache
 */

public class CacheResponse {

/**
 * The Cache contains no information about the requested name/type/class.
 */
static final byte UNKNOWN	= 0;

/**
 * The Cache has determined that there is no information about the
 * requested name/type/class.
 */
static final byte NEGATIVE	= 1;

/**
 * The Cache has partially answered the question for the
 * requested name/type/class.  This normally occurs when a CNAME is
 * found, but type/class information for the CNAME's taget is unknown.
 * @see CNAMERecord
 */
static final byte PARTIAL	= 2;

/**
 * The Cache has successfully answered the question for the
 * requested name/type/class.
 */
static final byte SUCCESSFUL	= 3;

private byte type;
private Object data;
private Vector backtrace;

private
CacheResponse() {}

CacheResponse(byte _type, Object _data) {
	type = _type;
	data = _data;
}

CacheResponse(byte _type) {
	this(_type, null);
}

/**
 * Sets a CacheResponse to have a different value without destroying the 
 * backtrace
 */
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
addCNAME(CNAMERecord cname) {
	if (backtrace == null)
		backtrace = new Vector();
	backtrace.addElement(cname);
}

/** Is the answer to the query unknown? */
public boolean
isUnknown() {
	return (type == UNKNOWN);
}

/** Is the answer to the query conclusively negative? */
public boolean
isNegative() {
	return (type == NEGATIVE);
}

/** Did the query partially succeed? */
public boolean
isPartial() {
	return (type == PARTIAL);
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
 * If the query was partially successful, return the last CNAME found in
 * the lookup process.
 */
public CNAMERecord
partial() {
	if (type != SUCCESSFUL)
		return null;
	return (CNAMERecord) data;
}

/**
 * If the query involved CNAME traversals, return a Vector containing all
 * CNAMERecords traversed.
 */
public Vector
backtrace() {
	return backtrace;
}

/** Prints the value of the CacheResponse */
public String
toString() {
	switch (type) {
		case UNKNOWN:	return "unknown";
		case NEGATIVE:	return "negative";
		case PARTIAL:	return "partial: reached " + data;
		case SUCCESSFUL:return "successful";
		default:	return null;
	}
}

}
