// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import DNS.utils.*;

class NameSet {

private Hashtable data;

protected
NameSet() {
	data = new Hashtable();
}

protected Object
findSet(Name name, short type) {
	Hashtable nameInfo = (Hashtable) data.get(name);
	if (nameInfo == null)
		return null;
	return nameInfo.get(new Short(type));
}

protected Hashtable
findName(Name name) {
	return (Hashtable) data.get(name);
}

protected void
addSet(Name name, short type, Object o) {
	Hashtable nameInfo = (Hashtable) data.get(name);
	if (nameInfo == null)
		data.put(name, nameInfo = new Hashtable());
	nameInfo.put(new Short(type), o);
}

public String
toString() {
	StringBuffer sb = new StringBuffer();
	Enumeration e = data.elements();
	while (e.hasMoreElements()) {
		Hashtable nameInfo = (Hashtable) e.nextElement();
		Enumeration e2 = nameInfo.elements();
		while (e2.hasMoreElements())
			sb.append(e2.nextElement());
	}
	return sb.toString();
}
	
}
