// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;

public class dnsMessage {

private dnsHeader header;
private Vector [] sections;
private int size;

public
dnsMessage(int id) {
	sections = new Vector[4];
	for (int i=0; i<4; i++)
		sections[i] = new Vector();
	header = new dnsHeader(id);
}

public
dnsMessage() {
	this(dnsHeader.randomID());
}

public
dnsMessage(CountedDataInputStream in) throws IOException {
	this();
	int startpos = in.getPos();
	dnsCompression c = new dnsCompression();
	header = new dnsHeader(in);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < header.getCount(i); j++) {
			dnsRecord rec = dnsRecord.fromWire(in, i, c);
			sections[i].addElement(rec);
		}
	}
	size = in.getPos() - startpos;
}

public
dnsMessage(byte [] b) throws IOException {
	this(new CountedDataInputStream(new ByteArrayInputStream(b)));
}

public void
setHeader(dnsHeader h) {
	header = h;
}

public dnsHeader
getHeader() {
	return header;
}

public void
addRecord(int section, dnsRecord r) {
	sections[section].addElement(r);
	header.incCount(section);
}

public boolean
removeRecord(int section, dnsRecord r) {
	if (sections[section].removeElement(r)) {
		header.decCount(section);
		return true;
	}
	else
		return false;
}

public dnsTSIGRecord
getTSIG() {
	int count = header.getCount(dns.ADDITIONAL);
	if (count == 0)
		return null;
	Vector v = sections[dns.ADDITIONAL];
	dnsRecord rec = (dnsRecord) v.elementAt(count - 1);
	if (rec.type !=  dns.TSIG)
		return null;
	return (dnsTSIGRecord) rec;
}

public Enumeration
getSection(int section) {
	return sections[section].elements();
}

public void
toWire(CountedDataOutputStream out) throws IOException {
	header.toWire(out);
	dnsCompression c = new dnsCompression();
	for (int i=0; i<4; i++) {
		if (sections[i].size() == 0)
			continue;
		for (int j=0; j<sections[i].size(); j++) {
			dnsRecord rec = (dnsRecord)sections[i].elementAt(j);
			rec.toWire(out, i, c);
		}
	}
}

public byte []
toWire() throws IOException {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	CountedDataOutputStream dout = new CountedDataOutputStream(out);
	toWire(dout);
	return out.toByteArray();
}

public void
toWireCanonical(CountedDataOutputStream out) throws IOException {
	header.toWire(out);
	for (int i=0; i<4; i++) {
		if (sections[i].size() == 0)
			continue;
		for (int j=0; j<sections[j].size(); j++) {
			dnsRecord rec = (dnsRecord)sections[i].elementAt(j);
			rec.toWireCanonical(out, i);
		}
	}
}

public int
numBytes() {
	return size;
}

public String
sectionToString(int i) {
	if (i > 3)
		return null;

	Enumeration e = getSection(i);
	StringBuffer sb = new StringBuffer();
	sb.append(";; " + dns.longSectionString(i) + ":\n");

	while (e.hasMoreElements()) {
		dnsRecord rec = (dnsRecord) e.nextElement();
		if (i == dns.QUESTION) {
			sb.append(";;\t" + rec.name);
			sb.append(", type = " + dns.typeString(rec.type));
			sb.append(", class = " + dns.classString(rec.dclass));
		}
		else
			sb.append(rec);
		sb.append("\n");
	}
	return sb.toString();
}

public String
toString() {
	StringBuffer sb = new StringBuffer();
	sb.append(getHeader() + "\n");
	for (int i = 0; i < 4; i++)
		sb.append(sectionToString(i) + "\n");
	sb.append(";; done (" + numBytes() + " bytes)");
	return sb.toString();
}

}
