// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import DNS.utils.*;

public class CacheResponse {

static final byte UNKNOWN	= 0;
static final byte NEGATIVE	= 1;
static final byte PARTIAL	= 2;
static final byte SUCCESSFUL	= 3;

byte type;
Object data;

CacheResponse(byte _type, Object _data) {
	type = _type;
	data = _data;
}

CacheResponse(byte _type) {
	this(_type, null);
}

public boolean
isUnknown() {
	return (type == UNKNOWN);
}

public boolean
isNegative() {
	return (type == NEGATIVE);
}

public boolean
isPartial() {
	return (type == PARTIAL);
}

public boolean
isSuccessful() {
	return (type == SUCCESSFUL);
}

public RRset
answer() {
	if (type != SUCCESSFUL)
		return null;
	return (RRset) data;
}

public Name
partial() {
	if (type != SUCCESSFUL)
		return null;
	return (Name) data;
}

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
