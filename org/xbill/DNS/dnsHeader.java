// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsHeader {

private int id; 
private boolean [] flags;
byte rcode, opcode;
private short [] counts;

public
dnsHeader(int _id) {
	counts = new short[4];
	flags = new boolean[16];
	id = _id;
}

public
dnsHeader(CountedDataInputStream in) throws IOException {
	this(in.readUnsignedShort());
	readFlags(in);
	for (int i=0; i<counts.length; i++)
		counts[i] = in.readShort();
}

public void
toWire(CountedDataOutputStream out) throws IOException {
	out.writeShort(id);
	writeFlags(out);
	for (int i=0; i<counts.length; i++)
		out.writeShort(counts[i]);
}

public byte []
toWire() throws IOException {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	CountedDataOutputStream dout = new CountedDataOutputStream(out);
	toWire(dout);
	return out.toByteArray();
}

public void
setFlag(int bit) {
	flags[bit] = true;
}

public void
unsetFlag(int bit) {
	flags[bit] = false;
}

public boolean
getFlag(int bit) {
	return flags[bit];
}

public int
getID() {
	return id;
}

public void
setID(int _id) {
	id = _id;
}

static short
randomID() {
	// why can't this be static?
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
setCount(int field, short value) {
	counts[field] = value;
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
writeFlags(CountedDataOutputStream out) throws IOException {
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
readFlags(CountedDataInputStream in) throws IOException {
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
		if (getFlag(i) && ((s = dns.flagString(i)) != null)) {
			sb.append(s);
			sb.append(" ");
		}
	return sb.toString();
}

public String
toString() {
	StringBuffer sb = new StringBuffer();

	sb.append(";; ->>HEADER<<- "); 
	sb.append("opcode: " + dns.opcodeString(getOpcode()));
	sb.append(", status: " + dns.rcodeString(getRcode()));
	sb.append(", id: " + getID());
	sb.append("\n");

	sb.append(";; flags: " + printFlags());
	sb.append("; ");
	for (int i = 0; i < 4; i++)
		sb.append(dns.sectionString(i) + ": " + getCount(i) + " ");
	return sb.toString();
}

}
