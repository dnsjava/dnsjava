// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class Header {

private int id; 
private boolean [] flags;
byte rcode, opcode;
private short [] counts;

public
Header(int _id) {
	counts = new short[4];
	flags = new boolean[16];
	id = _id;
}

public
Header() {
	this(-1);
}

public
Header(DataByteInputStream in) throws IOException {
	this(in.readUnsignedShort());
	readFlags(in);
	for (int i=0; i<counts.length; i++)
		counts[i] = in.readShort();
}

public void
toWire(DataByteOutputStream out) throws IOException {
	if (id < 0)
		out.writeShort(randomID());
	else
		out.writeShort(id);
	writeFlags(out);
	for (int i=0; i<counts.length; i++)
		out.writeShort(counts[i]);
}

public byte []
toWire() throws IOException {
	DataByteOutputStream out = new DataByteOutputStream();
	toWire(out);
	return out.toByteArray();
}

public void
setFlag(int bit) {
	flags[bit] = true;
}

void
setFlags(boolean [] _flags) {
	flags = flags;
}

public void
unsetFlag(int bit) {
	flags[bit] = false;
}

public boolean
getFlag(int bit) {
	return flags[bit];
}

boolean []
getFlags() {
	return flags;
}

public int
getID() {
	if (id < 0)
		id = randomID();
	return id & 0xFFFF;
}

public void
setID(int _id) {
	id = _id;
}

static short
randomID() {
	Random random = new Random();
	return (short) (random.nextInt() & 0xFFFF);
}

public void
setRcode(byte value) {
	rcode = value;
}

public byte
getRcode() {
	return rcode;
}

public void
setOpcode(byte value) {
	opcode = value;
}

public byte
getOpcode() {
	return opcode;
}

public void
setCount(int field, int value) {
	counts[field] = (short) value;
}

public void
incCount(int field) {
	counts[field]++;
}

public void
decCount(int field) {
	counts[field]--;
}

public short
getCount(int field) {
	return counts[field];
}

private void
writeFlags(DataByteOutputStream out) throws IOException {
	short flags1 = 0, flags2 = 0;
	for (int i = 0; i < 8; i++) {
		if (flags[i])	flags1 |= (1 << (7-i));
		if (flags[i+8])	flags2 |= (1 << (7-i));
	}
	flags1 |= (opcode << 3);
	flags2 |= (rcode);
	out.writeByte(flags1);
	out.writeByte(flags2);
}

private void
readFlags(DataByteInputStream in) throws IOException {
	short flags1 = (short)in.readUnsignedByte();
	short flags2 = (short)in.readUnsignedByte();
	for (int i = 0; i < 8; i++) {
		flags[i] =	((flags1 & (1 << (7-i))) != 0);
		flags[i+8] =	((flags2 & (1 << (7-i))) != 0);
	}
	opcode = (byte) ((flags1 >> 3) & 0xF);
	rcode = (byte) (flags2 & 0xF);
}

public String
printFlags() {
	String s;
	StringBuffer sb = new StringBuffer();

	for (int i = 0; i < flags.length; i++)
		if (getFlag(i) && ((s = Flags.string(i)) != null)) {
			sb.append(s);
			sb.append(" ");
		}
	return sb.toString();
}

public String
toString() {
	StringBuffer sb = new StringBuffer();

	sb.append(";; ->>HEADER<<- "); 
	sb.append("opcode: " + Opcode.string(getOpcode()));
	sb.append(", status: " + Rcode.string(getRcode()));
	sb.append(", id: " + getID());
	sb.append("\n");

	sb.append(";; flags: " + printFlags());
	sb.append("; ");
	for (int i = 0; i < 4; i++)
		sb.append(Section.string(i) + ": " + getCount(i) + " ");
	return sb.toString();
}

public Object
clone() {
	Header h = new Header();
	for (int i = 0; i < counts.length; i++)
		h.counts[i] = counts[i];	
	for (int i = 0; i < flags.length; i++)
		h.flags[i] = flags[i];	
	h.id = id;
	h.rcode = rcode;
	h.rcode = rcode;
	h.opcode = opcode;
	return h;
}

}
