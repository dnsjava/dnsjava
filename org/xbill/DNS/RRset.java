// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;

public class RRset {

private Vector rrs;
private Vector sigs;

public RRset() {
	rrs = new Vector();
	sigs = new Vector();
}

public void
addRR(Record r) {
	if (r.getType() != Type.SIG) {
		if (!rrs.contains(r))
			rrs.addElement(r);
	}
	else {
		if (!sigs.contains(r))
			sigs.addElement(r);
	}
}

public void
clear() {
	rrs.setSize(0);
	sigs.setSize(0);
}

public Enumeration
rrs() {
	return rrs.elements();
}

public Enumeration
sigs() {
	return sigs.elements();
}

public int
size() {
	return rrs.size();
}

public Name
getName() {
	Record r =  (Record) rrs.elementAt(0);
	return r.getName();
}

public short
getType() {
	Record r =  (Record) rrs.elementAt(0);
	return r.getType();
}

public int
getTTL() {
	int ttl = Integer.MAX_VALUE;
	Enumeration e = rrs();
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		if (r.getTTL() < ttl)
			ttl = r.getTTL();
	}
	return ttl;
}

public String
toString() {
	StringBuffer sb = new StringBuffer();
	sb.append("{ [");
	Enumeration e = rrs();
	while (e.hasMoreElements()) {
		Record rr = (Record) e.nextElement();
		sb.append(rr);
		if (e.hasMoreElements())
			sb.append("<>");
	}
	sb.append("] [");
	e = sigs();
	while (e.hasMoreElements()) {
		Record rr = (Record) e.nextElement();
		sb.append(rr);
		if (e.hasMoreElements())
			sb.append("<>");
	}
	sb.append("] }");
	return sb.toString();
}

}
