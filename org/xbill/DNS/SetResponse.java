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
 * The Cache contains no information about the requested name/type/class.
 */
static final byte UNKNOWN	= 0;

/**
 * The Cache has determined that there is no information about the
 * requested name/type/class.
 */
static final byte NEGATIVE	= 1;

/**
 * The Zone does not contain the requested name
 * requested name/type/class.
 */
static final byte NXDOMAIN	= 2;

/**
 * The Zone contains the name, but no data of the requested type/class
 */
static final byte NODATA        = 3;


/**
 * The Cache/Zone has partially answered the question for the
 * requested name/type/class.  This normally occurs when a CNAME is
 * found that points to data unknown in the Cache or outside of the Zone.
 * @see CNAMERecord
 */
static final byte PARTIAL	= 4;

/**
 * The Cache/Zone has successfully answered the question for the
 * requested name/type/class.
 */
static final byte SUCCESSFUL	= 5;

private byte type;
private Object data;
private Vector backtrace;

private
SetResponse() {}

SetResponse(byte _type, Object _data) {
	type = _type;
	data = _data;
}

SetResponse(byte _type) {
	this(_type, null);
}

/** Changes the value of a SetResponse without destroying the backtrace */
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
	backtrace.insertElementAt(cname, 0);
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

/** Is the answer to the query that the name does not exist? */
public boolean
isNXDOMAIN() {
	return (type == NXDOMAIN);
}

/** Is the answer to the query that the data does not exist? */
public boolean
isNODATA() {
	return (type == NODATA);
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
		case NXDOMAIN:	return "NXDOMAIN";
		case NODATA:	return "NODATA";
		case PARTIAL:	return "partial: reached " + data;
		case SUCCESSFUL:return "successful";
		default:	return null;
	}
}

}
