// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;

public class RRset {

private Vector rrs;
private Vector sigs;
private Name name;
private short type;

public RRset(Name _name, short _type) {
	rrs = new Vector();
	sigs = new Vector();
	name = _name;
	type = _type;
}

public void
addRR(Record r) {
	rrs.addElement(r);
}

public void
addSIG(SIGRecord r) {
	sigs.addElement(r);
}

public Enumeration
rrs() {
	return rrs.elements();
}

public Enumeration
sigs() {
	return sigs.elements();
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
