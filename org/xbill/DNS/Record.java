// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * The base class that all records are derived from.
 *
 * @author Brian Wellington
 */

abstract public class Record implements Cloneable {

protected Name name;
protected short type, dclass;
protected int ttl;
protected int wireLength = -1;

private	static Class [] knownTypes = new Class[256];

private static Class [] fromWireList = new Class [] {Name.class,
                                                     Short.TYPE,
                                                     Integer.TYPE,
                                                     Integer.TYPE,
                                                     DataByteInputStream.class,
                                                     Compression.class};
private static Class [] fromTextList = new Class [] {Name.class,
						     Short.TYPE,
						     Integer.TYPE,
						     MyStringTokenizer.class,
						     Name.class};

protected
Record() {}

Record(Name _name, short _type, short _dclass, int _ttl) {
	name = _name;
	type = _type;
	dclass = _dclass;
	ttl = _ttl;
}

private static final Class
toClass(short type) throws ClassNotFoundException {
	/*
	 * First, see if we've already found this type.
	 */
	if (type < 0 || type > 255)
		throw new ClassNotFoundException();
	if (knownTypes[type] != null)
		return knownTypes[type];

	String s = Record.class.toString();
	/*
	 * Remove "class " from the beginning, and "Record" from the end.
	 * Then construct the new class name.
	 */
	knownTypes[type] = Class.forName(s.substring(6, s.length() - 6) +
					 Type.string(type) + "Record");
	return knownTypes[type];
}

private static Record
newRecord(Name name, short type, short dclass, int ttl, int length,
	  DataByteInputStream in, Compression c) throws IOException
{
	Record rec;
	int recstart;
	if (in == null)
		recstart = 0;
	else
		recstart = in.getPos();

	try {
		Class rrclass;
		Constructor m;

		rrclass = toClass(type);
		m = rrclass.getDeclaredConstructor(fromWireList);
		rec = (Record) m.newInstance(new Object [] {
							name,
							new Short(dclass),
							new Integer(ttl),
							new Integer(length),
							in, c
						});
	}
	catch (ClassNotFoundException e) {
		rec = new UNKRecord(name, type, dclass, ttl, length, in, c);
	}
	catch (InvocationTargetException e) {
		if (e.getTargetException() instanceof IOException)
			throw (IOException) e.getTargetException();
		if (Options.check("verbose")) {
			System.err.println("new record: " + e);
			System.err.println(e.getTargetException());
		}
		return null;
	}
	catch (Exception e) {
		if (Options.check("verbose"))
			System.err.println("new record: " + e);
		return null;
	}
	if (in != null && in.getPos() - recstart != length)
		throw new IOException("Invalid record length");
	rec.wireLength = length;
	return rec;
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
	int start;

	start = in.getPos();

	name = new Name(in, c);

	type = in.readShort();
	dclass = in.readShort();

	if (section == Section.QUESTION)
		return newRecord(name, type, dclass);

	ttl = in.readInt();
	length = in.readShort();
	if (length == 0)
		return newRecord(name, type, dclass, ttl);
	rec = newRecord(name, type, dclass, ttl, length, in, c);
	rec.wireLength = in.getPos() - start;
	return rec;
}

/**
 * Builds a Record from DNS uncompressed wire format.
 */
public static Record
fromWire(byte [] b, int section) throws IOException {
	DataByteInputStream in = new DataByteInputStream(b);
	return fromWire(in, section, null);
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
toWireCanonical() throws IOException {
	DataByteOutputStream out = new DataByteOutputStream();
	toWireCanonical(out);
	return out.toByteArray();
}

/**
 * Converts the rdata in a Record into canonical DNS uncompressed wire format
 * (all names are converted to lowercase).
 */
public byte []
rdataToWireCanonical() throws IOException {
	DataByteOutputStream out = new DataByteOutputStream();
	rrToWireCanonical(out);
	return out.toByteArray();
}

public abstract String rdataToString();

/**
 * Converts a Record into a String representation
 */
public String
toString() {
	StringBuffer sb = new StringBuffer();
	sb.append(name);
	sb.append("\t");
	if (Options.check("BINDTTL"))
		sb.append(TTL.format(ttl));
	else
		sb.append((long)ttl & 0xFFFFFFFFL);
	sb.append(" ");
	if (dclass != DClass.IN || !Options.check("noPrintIN")) {
		sb.append(DClass.string(dclass));
		sb.append(" ");
	}
	sb.append(Type.string(type));
	sb.append("\t\t");
	if (wireLength != 0)
		sb.append(rdataToString());
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

	String s = st.nextToken();
	/* the string tokenizer loses the \\. */
	if (s.equals("#")) {
		s = st.nextToken();
		short length = Short.parseShort(s);
		s = st.remainingTokens();
		byte [] data = base16.fromString(s);
		if (length != data.length)
			throw new IOException("Invalid unknown RR encoding: " +
					      "length mismatch");
		DataByteInputStream in = new DataByteInputStream(data);
		rec = newRecord(name, type, dclass, ttl, length, in, null);
	}
	st.putBackToken(s);

	try {
		Class rrclass;
		Constructor m;

		rrclass = toClass(type);
		m = rrclass.getDeclaredConstructor(fromTextList);
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
		if (Options.check("verbose")) {
			System.err.println("from text: " + e);
			System.err.println(e.getTargetException());
		}
		return null;
	}
	catch (Exception e) {
		if (Options.check("verbose"))
			System.err.println("from text: " + e);
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
void
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

/**
 * Creates a new record identical to the current record, but with a different
 * name.  This is most useful for replacing the name of a wildcard record.
 */
public Record
withName(Name name) {
	Record rec = null;
	try {
		rec = (Record) clone();
	}
	catch (CloneNotSupportedException e) {
	}
	rec.name = name;
	return rec;
}

}
