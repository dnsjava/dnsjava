// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import DNS.utils.*;

/**
 * The base class that all records are derived from.
 */

abstract public class Record {

protected Name name;
protected short type, dclass;
protected int ttl;
protected int wireLength = -1;

protected
Record() {}

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

private static Record
newRecord(Name name, short type, short dclass, int ttl, int length,
	  DataByteInputStream in, Compression c) throws IOException
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
						DataByteInputStream.class,
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

/**
 * Creates a new record, with the given parameters.
 * @return An object of a type extending Record
 */
public static Record
newRecord(Name name, short type, short dclass, int ttl, int length,
	  byte [] data)
{
	DataByteInputStream dbs;
	if (data != null)
		dbs = new DataByteInputStream(data);
	else
		dbs = null;
	try {
		return newRecord(name, type, dclass, ttl, length, dbs, null);
	}
	catch (IOException e) {
		return null;
	}
}

/**
 * Creates a new empty record, with the given parameters.
 * @return An object of a type extending Record
 */
public static Record
newRecord(Name name, short type, short dclass, int ttl) {
	return newRecord(name, type, dclass, ttl, 0, null);
}

/**
 * Creates a new empty record, with the given parameters.  This method is
 * designed to create records that will be added to the QUERY section
 * of a message.
 * @return An object of a type extending Record
 */
public static Record
newRecord(Name name, short type, short dclass) {
	return newRecord(name, type, dclass, 0, 0, null);
}

static Record
fromWire(DataByteInputStream in, int section, Compression c)
throws IOException
{
	short type, dclass;
	int ttl;
	short length;
	Name name;
	Record rec;
	int start, datastart;

	start = in.getPos();

	name = new Name(in, c);

	type = in.readShort();
	dclass = in.readShort();

	if (section == Section.QUESTION)
		return newRecord(name, type, dclass);

	ttl = in.readInt();
	length = in.readShort();
	datastart = in.getPos();
	rec = newRecord(name, type, dclass, ttl, length, in, c);
	if (in.getPos() - datastart != length)
		throw new IOException("Invalid record length");
	rec.wireLength = in.getPos() - start;
	return rec;
}

void
toWire(DataByteOutputStream out, int section, Compression c)
throws IOException
{
	int start = out.getPos();
	name.toWire(out, c);
	out.writeShort(type);
	out.writeShort(dclass);
	if (section == Section.QUESTION)
		return;
	out.writeInt(ttl);
	int lengthPosition = out.getPos();
	out.writeShort(0); /* until we know better */
	rrToWire(out, c);
	out.writeShortAt(out.getPos() - lengthPosition - 2, lengthPosition);
	wireLength = out.getPos() - start;
}

/**
 * Converts a Record into DNS uncompressed wire format.
 */
public byte []
toWire(int section) throws IOException {
	DataByteOutputStream out = new DataByteOutputStream();
	toWire(out, section, null);
	return out.toByteArray();
}

void
toWireCanonical(DataByteOutputStream out) throws IOException {
	name.toWireCanonical(out);
	out.writeShort(type);
	out.writeShort(dclass);
	out.writeInt(ttl);
	int lengthPosition = out.getPos();
	out.writeShort(0); /* until we know better */
	rrToWireCanonical(out);
	out.writeShortAt(out.getPos() - lengthPosition - 2, lengthPosition);
}

/**
 * Converts a Record into canonical DNS uncompressed wire format (all names are
 * converted to lowercase).
 */
public byte []
toWireCanonical(int section) throws IOException {
	DataByteOutputStream out = new DataByteOutputStream();
	toWireCanonical(out);
	return out.toByteArray();
}


StringBuffer
toStringNoData() {
	StringBuffer sb = new StringBuffer();
	sb.append(name);
	sb.append("\t");
	sb.append(ttl);
	sb.append("\t");
	sb.append(DClass.string(dclass));
	sb.append("\t");
	sb.append(Type.string(type));
	sb.append("\t");
	return sb;
}

/**
 * Converts a Record into a String representation
 */
public String
toString() {
	StringBuffer sb = toStringNoData();
	sb.append("<unknown format>");
	return sb.toString();
}

/**
 * Builds a new Record from its textual representation
 */
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

/**
 * Returns the record's name
 * @see Name
 */
public Name
getName() {
	return name;
}

/**
 * Returns record's type
 * @see Type
 */
public short
getType() {
	return type;
}

/**
 * Returns the type of RRset that this record would belong to.  For all types
 * except SIGRecord, this is equivalent to getType().
 * @return The type of record, if not SIGRecord.  If the type is SIGRecord,
 * the type covered is returned.
 * @see Type
 * @see RRset
 * @see SIGRecord
 */
public short
getRRsetType() {
	if (type == Type.SIG) {
		SIGRecord sig = (SIGRecord) this;
		return sig.getTypeCovered();
	}
	return type;
}

/**
 * Returns the record's class
 */
public short
getDClass() {
	return dclass;
}

/**
 * Returns the record's TTL
 */
public int
getTTL() {
	return ttl;
}

/**
 * Returns the length of this record in wire format, based on the last time
 * this record was parsed from data or converted to data.  The wire format
 * may or may not be compressed
 * @return The last known length, or -1 if the record has never been in wire
 * format
 */
public short
getWireLength() {
	return (short) wireLength;
}

/**
 * Converts the type-specific RR to wire format - must be overriden
 */
abstract void rrToWire(DataByteOutputStream out, Compression c) throws IOException;

/**
 * Converts the type-specific RR to canonical wire format - must be overriden
 * if the type-specific RR data includes a Name
 * @see Name
 */
byte []
rrToWireCanonical(DataByteOutputStream out) throws IOException {
	rrToWire(out, null);
}

/**
 * Determines if two Records are identical
 */
public boolean
equals(Object arg) {
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

/**
 * Generates a hash code based on the Record's data
 */
public int
hashCode() {
	try {
		byte [] array1 = toWire(Section.ANSWER);
		return array1.hashCode();
	}
	catch (IOException e) {
		return 0;
	}
}

}
