// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import DNS.utils.*;

public class Message {

private Header header;
private Vector [] sections;
private int size;

public
Message(int id) {
	sections = new Vector[4];
	for (int i=0; i<4; i++)
		sections[i] = new Vector();
	header = new Header(id);
}

public
Message() {
	this(Header.randomID());
}

public
Message(CountedDataInputStream in) throws IOException {
	this();
	int startpos = in.getPos();
	Compression c = new Compression();
	header = new Header(in);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < header.getCount(i); j++) {
			Record rec = Record.fromWire(in, i, c);
			sections[i].addElement(rec);
		}
	}
	size = in.getPos() - startpos;
}

public
Message(byte [] b) throws IOException {
	this(new CountedDataInputStream(new ByteArrayInputStream(b)));
}

public void
setHeader(Header h) {
	header = h;
}

public Header
getHeader() {
	return header;
}

public void
addRecord(int section, Record r) {
	sections[section].addElement(r);
	header.incCount(section);
}

public boolean
removeRecord(int section, Record r) {
	if (sections[section].removeElement(r)) {
		header.decCount(section);
		return true;
	}
	else
		return false;
}

public TSIGRecord
getTSIG() {
	int count = header.getCount(Section.ADDITIONAL);
	if (count == 0)
		return null;
	Vector v = sections[Section.ADDITIONAL];
	Record rec = (Record) v.elementAt(count - 1);
	if (rec.type !=  Type.TSIG)
		return null;
	return (TSIGRecord) rec;
}

public Enumeration
getSection(int section) {
	return sections[section].elements();
}

public void
toWire(CountedDataOutputStream out) throws IOException {
	header.toWire(out);
	Compression c = new Compression();
	for (int i=0; i<4; i++) {
		if (sections[i].size() == 0)
			continue;
		for (int j=0; j<sections[i].size(); j++) {
			Record rec = (Record)sections[i].elementAt(j);
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
	sb.append(";; " + Section.longString(i) + ":\n");

	while (e.hasMoreElements()) {
		Record rec = (Record) e.nextElement();
		if (i == Section.QUESTION) {
			sb.append(";;\t" + rec.name);
			sb.append(", type = " + Type.string(rec.type));
			sb.append(", class = " + DClass.string(rec.dclass));
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
