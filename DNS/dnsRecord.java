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

abstract public class dnsRecord {

dnsName name;
short type, dclass;
int ttl;
int oLength;

dnsRecord(dnsName _name, short _type, short _dclass, int _ttl) {
	name = _name;
	type = _type;
	dclass = _dclass;
	ttl = _ttl;
}

static dnsRecord
newRecord(dnsName name, short type, short dclass, int ttl, int length,
	  CountedDataInputStream in, dnsCompression c) throws IOException
{
	String s = dns.typeString(type);
	dnsRecord rec;
	try {
		Class rrclass;
		Constructor m;

		rrclass = Class.forName("dns" + s + "Record");
		m = rrclass.getConstructor(new Class [] {
						dnsName.class,
						Short.TYPE,
						Integer.TYPE,
						Integer.TYPE,
						CountedDataInputStream.class,
						dnsCompression.class
					   });
		rec = (dnsRecord) m.newInstance(new Object [] {
							name,
							new Short(dclass),
							new Integer(ttl),
							new Integer(length),
							in, c
						});
		rec.oLength = length;
		return rec;
	}
	catch (ClassNotFoundException e) {
		rec = new dnsUNKRecord(name, type, dclass, ttl, length, in, c);
		rec.oLength = length;
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


public static dnsRecord
newRecord(dnsName name, short type, short dclass, int ttl, int length,
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

public static dnsRecord
newRecord(dnsName name, short type, short dclass, int ttl) {
	return newRecord(name, type, dclass, ttl, 0, null);
}

public static dnsRecord
newRecord(dnsName name, short type, short dclass) {
	return newRecord(name, type, dclass, 0, 0, null);
}

public static dnsRecord
fromWire(CountedDataInputStream in, int section, dnsCompression c)
throws IOException
{
	short type, dclass;
	int ttl;
	short length;
	dnsName name;
	dnsRecord rec;

	name = new dnsName(in, c);

	type = in.readShort();
	dclass = in.readShort();

	if (section == dns.QUESTION)
		return newRecord(name, type, dclass);

	ttl = in.readInt();
	length = in.readShort();
	rec = newRecord(name, type, dclass, ttl, length, in, c);
	return rec;
}

public void
toWire(CountedDataOutputStream out, int section, dnsCompression c)
throws IOException
{
	name.toWire(out, c);
	out.writeShort(type);
	out.writeShort(dclass);
	if (section == dns.QUESTION)
		return;
	out.writeInt(ttl);
	byte [] data = rrToWire(c);
	if (data == null)
		out.writeShort(0);
	else {
		out.writeShort(data.length);
		out.write(data);
	}

}

public byte []
toWire(int section) throws IOException {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	CountedDataOutputStream dout = new CountedDataOutputStream(out);
	toWire(dout, section, null);
	return out.toByteArray();
}

void
toWireCanonical(CountedDataOutputStream out, int section) throws IOException {
	name.toWireCanonical(out);
	out.writeShort(type);
	out.writeShort(dclass);
	if (section == dns.QUESTION)
		return;
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
	if (dclass != dns.IN) {
		sb.append("\t");
		sb.append(dns.classString(dclass));
	}
	sb.append("\t");
	sb.append(dns.typeString(type));
	sb.append("\t");
	return sb;
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	sb.append("<unknown format>");
	return sb.toString();
}

public static dnsRecord
fromString(dnsName name, short type, short dclass, int ttl,
	   MyStringTokenizer st, dnsName origin)
throws IOException
{
	dnsRecord rec;

	try {
		Class rrclass;
		Constructor m;

		String s = dns.typeString(type);
		rrclass = Class.forName("dns" + s + "Record");
		m = rrclass.getConstructor(new Class [] {
						dnsName.class,
						Short.TYPE,
						Integer.TYPE,
						MyStringTokenizer.class,
						dnsName.class,
					   });
		rec = (dnsRecord) m.newInstance(new Object [] {
							name,
							new Short(dclass),
							new Integer(ttl),
							st, origin
						});
		return rec;
	}
	catch (ClassNotFoundException e) {
		rec = new dnsUNKRecord(name, type, dclass, ttl, st, origin);
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

public dnsName
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

abstract byte [] rrToWire(dnsCompression c) throws IOException;

byte [] rrToWireCanonical() throws IOException {
	return rrToWire(null);
}


}
