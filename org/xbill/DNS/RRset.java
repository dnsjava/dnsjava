// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;

public class RRset {

private Vector rrs;
private Name name;
private short type;

public RRset(Name _name, short _type) {
	rrs = new Vector();
	name = _name;
	type = _type;
}

public void
addRR(Record r) {
	rrs.addElement(r);
}

public Enumeration
rrs() {
	return rrs.elements();
}

}
