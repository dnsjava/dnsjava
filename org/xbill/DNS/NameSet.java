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
	Hashtable nameInfo = findName(name);
	if (nameInfo == null) {
		if (!name.isWild())
			nameInfo = findName(name.wild());
		if (nameInfo == null)
			return null;
	}
	Object o = nameInfo.get(new Short(type));
	if (o != null || type == Type.CNAME)
		return o;
	return nameInfo.get(new Short(Type.CNAME));
}

protected Object
findExactSet(Name name, short type) {
	Hashtable nameInfo = findName(name);
	if (nameInfo == null)
		return null;
	return nameInfo.get(new Short(type));
}

protected Hashtable
findName(Name name) {
	return (Hashtable) data.get(name);
}

protected void
addSet(Name name, short type, Object set) {
	Hashtable nameInfo = findName(name);
	if (nameInfo == null)
		data.put(name, nameInfo = new Hashtable());
	nameInfo.put(new Short(type), set);
}

protected void
removeSet(Name name, short type, Object set) {
	Hashtable nameInfo = findName(name);
	if (nameInfo == null) {
		if (!name.isWild()) {
			name = name.wild();
			nameInfo = findName(name);
		}
		if (nameInfo == null)
			return;
	}
	Object o = nameInfo.get(new Short(type));
	if (o != set && type != Type.CNAME) {
		type = Type.CNAME;
		o = nameInfo.get(new Short(type));
	}
	if (o == set) {
		nameInfo.remove(new Short(type));
		if (nameInfo.isEmpty())
			data.remove(name);
	}
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
