// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import DNS.utils.*;

/**
 * The Response from a query to Zone.findRecords().
 * @see Zone
 */

public class ZoneResponse {

/**
 * The Zone does not that name
 */
static final byte NXDOMAIN	= 0;

/**
 * The Zone contains the name, but no data of the requested type
 */
static final byte NODATA	= 1;

/**
 * The Zone contains information that has allowed a partial lookup.
 * This normally occurs when a CNAME is found that points to data outside
 * of the Zone.
 * @see CNAMERecord
 */
static final byte PARTIAL	= 2;

/**
 * The Zone has successfully found the requested data.
 */
static final byte SUCCESSFUL	= 3;

private byte type;
private Object data;
private Vector backtrace;

private
ZoneResponse() {}

ZoneResponse(byte _type, Object _data) {
	type = _type;
	data = _data;
}

ZoneResponse(byte _type) {
	this(_type, null);
}

/**
 * Sets a ZoneResponse to have a different value without destroying the 
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

/** Prints the value of the ZoneResponse */
public String
toString() {
	switch (type) {
		case NXDOMAIN:	return "NXDOMAIN";
		case NODATA:	return "NODATA";
		case PARTIAL:	return "partial: reached " + data;
		case SUCCESSFUL:return "successful";
		default:	return null;
	}
}

}
