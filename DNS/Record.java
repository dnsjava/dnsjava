// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

// This class should be extended for each record type.  The individual
// types must provide:
//	constructors
//	toString()
// and may provide, if necessary:
//	toWireCanonical()
// and should provide
//	accessor functions

package DNS;

import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import DNS.utils.*;

abstract public class Record {

Name name;
short type, dclass;
int ttl;
int wireLength = -1;

Record(Name _name, short _type, short _dclass, int _ttl) {
	name = _name;
	type = _type;
	dclass = _dclass;
	ttl = _ttl;
}

private static Class
toClass(short type) throws ClassNotFoundException {
	return Class.forName("DNS." + Type.string(type) + "Record");
}

static Record
newRecord(Name name, short type, short dclass, int ttl, int length,
	  CountedDataInputStream in, Compression c) throws IOException
{
	Record rec;
	try {
		Class rrclass;
		Constructor m;

		rrclass = toClass(type);
		m = rrclass.getConstructor(new Class [] {
						Name.class,
						Short.TYPE,
						Integer.TYPE,
						Integer.TYPE,
						CountedDataInputStream.class,
						Compression.class
					   });
		rec = (Record) m.newInstance(new Object [] {
							name,
							new Short(dclass),
							new Integer(ttl),
							new Integer(length),
							in, c
						});
		return rec;
	}
	catch (ClassNotFoundException e) {
		rec = new UNKRecord(name, type, dclass, ttl, length, in, c);
		rec.wireLength = length;
		return rec;
	}
	catch (InvocationTargetException e) {
		System.out.println("new record: " + e);
		System.out.println(e.getTargetException());
		return null;
	}
	catch (Exception e) {
		System.out.println("new record: " + e);
		return null;
	}
}


public static Record
newRecord(Name name, short type, short dclass, int ttl, int length,
	  byte [] data)
{
	CountedDataInputStream cds;
	if (data != null) {
		ByteArrayInputStream bs = new ByteArrayInputStream(data);
		cds = new CountedDataInputStream(bs);
	}
	else
		cds = null;
	try {
		return newRecord(name, type, dclass, ttl, length, cds, null);
	}
	catch (IOException e) {
		return null;
	}
}

public static Record
newRecord(Name name, short type, short dclass, int ttl) {
	return newRecord(name, type, dclass, ttl, 0, null);
}

public static Record
newRecord(Name name, short type, short dclass) {
	return newRecord(name, type, dclass, 0, 0, null);
}

public static Record
fromWire(CountedDataInputStream in, int section, Compression c)
throws IOException
{
	short type, dclass;
	int ttl;
	short length;
	Name name;
	Record rec;
	int start;

	start = in.getPos();

	name = new Name(in, c);

	type = in.readShort();
	dclass = in.readShort();

	if (section == Section.QUESTION)
		return newRecord(name, type, dclass);

	ttl = in.readInt();
	length = in.readShort();
	rec = newRecord(name, type, dclass, ttl, length, in, c);
	rec.wireLength = in.getPos() - start;
	return rec;
}

public void
toWire(CountedDataOutputStream out, int section, Compression c)
throws IOException
{
	int start = out.getPos();
	name.toWire(out, c);
	out.writeShort(type);
	out.writeShort(dclass);
	if (section == Section.QUESTION)
		return;
	out.writeInt(ttl);
	byte [] data = rrToWire(c, out.getPos() + 2);
	if (data == null)
		out.writeShort(0);
	else {
		out.writeShort(data.length);
		out.write(data);
	}
	wireLength = out.getPos() - start;

}

public byte []
toWire(int section) throws IOException {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	CountedDataOutputStream dout = new CountedDataOutputStream(out);
	toWire(dout, section, null);
	return out.toByteArray();
}

public void /* XXX - shouldn't be public */
toWireCanonical(CountedDataOutputStream out) throws IOException {
	name.toWireCanonical(out);
	out.writeShort(type);
	out.writeShort(dclass);
	out.writeInt(ttl);
	byte [] data = rrToWireCanonical();
	if (data == null)
		out.writeShort(0);
	else {
		out.writeShort(data.length);
		out.write(data);
	}
}

StringBuffer
toStringNoData() {
	StringBuffer sb = new StringBuffer();
	sb.append(name);
	sb.append("\t");
	sb.append(ttl);
	if (dclass != DClass.IN) {
		sb.append("\t");
		sb.append(DClass.string(dclass));
	}
	sb.append("\t");
	sb.append(Type.string(type));
	sb.append("\t");
	return sb;
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	sb.append("<unknown format>");
	return sb.toString();
}

public static Record
fromString(Name name, short type, short dclass, int ttl,
	   MyStringTokenizer st, Name origin)
throws IOException
{
	Record rec;

	try {
		Class rrclass;
		Constructor m;

		rrclass = toClass(type);
		m = rrclass.getConstructor(new Class [] {
						Name.class,
						Short.TYPE,
						Integer.TYPE,
						MyStringTokenizer.class,
						Name.class,
					   });
		rec = (Record) m.newInstance(new Object [] {
						name,
						new Short(dclass),
						new Integer(ttl),
						st, origin
					     });
		return rec;
	}
	catch (ClassNotFoundException e) {
		rec = new UNKRecord(name, type, dclass, ttl, st, origin);
		return rec;
	}
	catch (InvocationTargetException e) {
		System.out.println("from text: " + e);
		System.out.println(e.getTargetException());
		return null;
	}
	catch (Exception e) {
		System.out.println("from text: " + e);
		return null;
	}
}

public Name
getName() {
	return name;
}

public short
getType() {
	return type;
}

public short
getDClass() {
	return dclass;
}

public short
getWireLength() {
	return (short) wireLength;
}

abstract byte [] rrToWire(Compression c, int index) throws IOException;

byte [] rrToWireCanonical() throws IOException {
	return rrToWire(null, 0);
}

public boolean
equals(Object arg) {
System.out.println("in Record.equals()");
System.out.println("1: " + this);
System.out.println("2: " + arg);
	if (arg == null || !(arg instanceof Record))
		return false;
	Record r = (Record) arg;
	try {
		byte [] array1 = toWire(Section.ANSWER);
		byte [] array2 = r.toWire(Section.ANSWER);
		if (array1.length != array2.length)
			return false;
		for (int i = 0; i < array1.length; i++)
			if (array1[i] != array2[i])
				return false;
		return true;
	}
	catch (IOException e) {
		return false;
	}
}

public int
hashCode() {
System.out.println("in Record.hashcode()");
	try {
		byte [] array1 = toWire(Section.ANSWER);
		return array1.hashCode();
	}
	catch (IOException e) {
		return 0;
	}
}

}
