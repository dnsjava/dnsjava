// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

// This class should be extended for each record type.  The individual
// types must provide:
//	constructors
//	toString()
// and may provide, if necessary:
//	toWireCanonical()
// and should provide
//	accessor functions

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
						java.lang.Short.TYPE,
						java.lang.Integer.TYPE,
						java.lang.Integer.TYPE,
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


static dnsRecord
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

static dnsRecord
newRecord(dnsName name, short type, short dclass, int ttl) {
	return newRecord(name, type, dclass, ttl, 0, null);
}

static dnsRecord
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
toWire(DataOutputStream out, int section) throws IOException {
	name.toWire(out);
	out.writeShort(type);
	out.writeShort(dclass);
	if (section == dns.QUESTION)
		return;
	out.writeInt(ttl);
	byte [] data = rrToWire();
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
	DataOutputStream dout = new DataOutputStream(out);
	toWire(dout, section);
	return out.toByteArray();
}

void
toWireCanonical(DataOutputStream out, int section) throws IOException {
	name.toWireCanonical(out);
	out.writeShort(type);
	out.writeShort(dclass);
	if (section == dns.QUESTION)
		return;
	out.writeInt(ttl);
	byte [] data = rrToWire();
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
	sb.append("\t");
	sb.append(dns.typeString(type));
	if (dclass != dns.IN) {
		sb.append("\t");
		sb.append(dns.classString(dclass));
	}
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
fromString(StringTokenizer st, dnsName name, int ttl, short type, short dclass)
throws IOException {
	dnsRecord rec;

	try {
		Class rrclass;
		Constructor m;

		String s = dns.typeString(type);
		rrclass = Class.forName("dns" + s + "Record");
		m = rrclass.getConstructor(new Class [] {
						dnsName.class,
						java.lang.Short.TYPE,
						java.lang.Integer.TYPE,
						StringTokenizer.class
					   });
		rec = (dnsRecord) m.newInstance(new Object [] {
							name,
							new Short(dclass),
							new Integer(ttl),
							st
						});
		return rec;
	}
	catch (ClassNotFoundException e) {
		rec = new dnsUNKRecord(name, type, dclass, ttl, st);
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

abstract byte [] rrToWire() throws IOException;

byte [] rrToWireCanonical() throws IOException {
	return rrToWire();
}


}
