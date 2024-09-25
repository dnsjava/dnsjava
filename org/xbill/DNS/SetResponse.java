// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;
import lombok.AccessLevel;
import lombok.Getter;

import static org.xbill.DNS.SetResponseType.CNAME;
import static org.xbill.DNS.SetResponseType.DELEGATION;
import static org.xbill.DNS.SetResponseType.DNAME;
import static org.xbill.DNS.SetResponseType.NXDOMAIN;
import static org.xbill.DNS.SetResponseType.NXRRSET;
import static org.xbill.DNS.SetResponseType.SUCCESSFUL;
import static org.xbill.DNS.SetResponseType.UNKNOWN;

/**
 * The Response from a query to Cache.lookupRecords() or Zone.findRecords()
 * @see Cache
 * @see Zone
 *
 * @author Brian Wellington
 */

public class SetResponse {

private static final SetResponse SR_UNKNOWN = new SetResponse(UNKNOWN, null, false);
private static final SetResponse SR_UNKNOWN_AUTH = new SetResponse(UNKNOWN, null, true);
private static final SetResponse SR_NXDOMAIN = new SetResponse(NXDOMAIN, null, false);
private static final SetResponse SR_NXDOMAIN_AUTH = new SetResponse(NXDOMAIN, null, true);
private static final SetResponse SR_NXRRSET = new SetResponse(NXRRSET, null, false);
private static final SetResponse SR_NXRRSET_AUTH = new SetResponse(NXRRSET, null, true);

private SetResponseType type;
@Getter(AccessLevel.PACKAGE)
private boolean isAuthenticated;
private Object data;

//private
//SetResponse() {}
//
//SetResponse(int type, RRset rrset) {
//	if (type < 0 || type > 6)
//		throw new IllegalArgumentException("invalid type");
//	this.type = type;
//	this.data = rrset;
//}
//
//SetResponse(int type) {
//	if (type < 0 || type > 6)
//		throw new IllegalArgumentException("invalid type");
//	this.type = type;
//	this.data = null;
//}
private SetResponse(SetResponseType type, RRset rrset, boolean isAuthenticated) {
	this.type = type;
	this.isAuthenticated = isAuthenticated;
	if (rrset != null) {
		addRRset(rrset);
	}
}

static SetResponse ofType(SetResponseType type) {
	return ofType(type, null, false);
}

static SetResponse ofType(SetResponseType type, Cache.CacheRRset rrset) {
	return ofType(type, rrset, rrset.isAuthenticated());
}

static SetResponse ofType(SetResponseType type, RRset rrset, boolean isAuthenticated) {
	switch (type) {
		case UNKNOWN:
			return isAuthenticated ? SR_UNKNOWN_AUTH : SR_UNKNOWN;
		case NXDOMAIN:
			return isAuthenticated ? SR_NXDOMAIN_AUTH : SR_NXDOMAIN;
		case NXRRSET:
			return isAuthenticated ? SR_NXRRSET_AUTH : SR_NXRRSET;
		case DELEGATION:
		case CNAME:
		case DNAME:
		case SUCCESSFUL:
			return new SetResponse(type, rrset, isAuthenticated);
		default:
			throw new IllegalArgumentException("invalid type");
	}
}

void
addRRset(RRset rrset) {
	if (data == null){
		data = new ArrayList();
		if (rrset instanceof Cache.CacheRRset) {
			isAuthenticated = ((Cache.CacheRRset) rrset).isAuthenticated();
		}
	} else {
		if (rrset instanceof Cache.CacheRRset && isAuthenticated) {
			isAuthenticated = ((Cache.CacheRRset) rrset).isAuthenticated();
		}
	}
	List l = (List) data;
	l.add(rrset);
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

/** Is the result of the lookup a CNAME? */
public boolean
isCNAME() {
	return (type == CNAME);
}

/** Is the result of the lookup a DNAME? */
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
	List l = (List) data;
	return (RRset []) l.toArray(new RRset[l.size()]);
}

/**
 * If the query encountered a CNAME, return it.
 */
public CNAMERecord
getCNAME() {
	return (CNAMERecord)((RRset)data).first();
}

/**
 * If the query encountered a DNAME, return it.
 */
public DNAMERecord
getDNAME() {
	return (DNAMERecord)((RRset)data).first();
}

/**
 * If the query hit a delegation point, return the NS set.
 */
public RRset
getNS() {
	return (RRset)data;
}

/** Prints the value of the SetResponse */
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
		default:		throw new IllegalStateException();
	}
}

}
