// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

class TypeClass {

private short type;
private short dclass;

TypeClass(short _type, short _dclass) {
	type = _type;
	dclass = _dclass;
}

public boolean
equals(Object arg) {
	if (arg == null || !(arg instanceof TypeClass))
		return false;
	TypeClass tc = (TypeClass) arg;
	return (type == tc.type && dclass == tc.dclass);
}

public int
hashCode() {
	return (dclass << 16) + type;
}

}
