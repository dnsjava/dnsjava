// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

/** A type/class pair.  Used for lookup purposes */

class TypeClass {

private short type;
private short dclass;

private
TypeClass() {}

TypeClass(short _type, short _dclass) {
	type = _type;
	dclass = _dclass;
}

public boolean
equals(Object arg) {
	if (arg == null || !(arg instanceof TypeClass))
		return false;
	TypeClass tc = (TypeClass) arg;
	boolean typeOK = (type == Type.ANY || tc.type == Type.ANY ||
			  type == tc.type);
	boolean classOK = (dclass == DClass.ANY || tc.dclass == DClass.ANY ||
			   dclass == tc.dclass);
	return (typeOK && classOK);
}

public int
hashCode() {
	return (dclass << 16) + type;
}

}
