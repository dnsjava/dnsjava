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

protected Object []
findSets(Name name, short type, short dclass) {
	Object [] array;
	Object o;

	Hashtable nameInfo = findName(name);
	if (nameInfo == null) 
		return null;
	if (type == Type.ANY) {
		synchronized (nameInfo) {
			array = new Object[nameInfo.size()];
			int i = 0;
			Enumeration e = nameInfo.elements();
			while (e.hasMoreElements())
				array[i++] = e.nextElement();
			}
		return array;
	}
	o = nameInfo.get(new TypeClass(type, dclass));
	if (o != null) {
		array = new Object[1];
		array[0] = o;
		return array;
	}
	if (type != Type.CNAME) {
		o = nameInfo.get(new TypeClass(Type.CNAME, dclass));
		if (o == null)
			return null;
		else {
			array = new Object[1];
			array[0] = o;
			return array;
		}
	}
	return null;
}

protected Object
findExactSet(Name name, short type, short dclass) {
	Hashtable nameInfo = findName(name);
	if (nameInfo == null)
		return null;
	return nameInfo.get(new TypeClass(type, dclass));
}

protected Hashtable
findName(Name name) {
	return (Hashtable) data.get(name);
}

protected void
addSet(Name name, short type, short dclass, Object set) {
	Hashtable nameInfo = findName(name);
	if (nameInfo == null)
		data.put(name, nameInfo = new Hashtable());
	synchronized (nameInfo) {
		nameInfo.put(new TypeClass(type, dclass), set);
	}
}

protected void
removeSet(Name name, short type, short dclass, Object set) {
	Hashtable nameInfo = findName(name);
	if (nameInfo == null)
		return;
	Object o = nameInfo.get(new TypeClass(type, dclass));
	if (o != set && type != Type.CNAME) {
		type = Type.CNAME;
		o = nameInfo.get(new TypeClass(type, dclass));
	}
	if (o == set) {
		synchronized (nameInfo) {
			nameInfo.remove(new TypeClass(type, dclass));
		}
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
