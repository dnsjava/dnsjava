// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * A DNS message header
 * @see Message
 *
 * @author Brian Wellington
 */

public class Header {

private int id; 
private boolean [] flags;
private short rcode;
private byte opcode;
private int [] counts;

/**
 * Create a new empty header.
 * @param id The message id
 */
public
Header(int _id) {
	counts = new int[4];
	flags = new boolean[16];
	id = _id;
}

/**
 * Create a new empty header with a random message id
 */
public
Header() {
	this(randomID());
}

/**
 * Parses a Header from a stream containing DNS wire format.  This normally
 * isn't useful to clients.
 */
public
Header(DataByteInputStream in) throws IOException {
	this(in.readUnsignedShort());
	readFlags(in);
	for (int i = 0; i<counts.length; i++)
		counts[i] = in.readUnsignedShort();
}

void
toWire(DataByteOutputStream out) throws IOException {
	out.writeShort(getID());
	writeFlags(out);
	for (int i = 0; i<counts.length; i++)
		out.writeShort((short)counts[i]);
}

public byte []
toWire() throws IOException {
	DataByteOutputStream out = new DataByteOutputStream();
	toWire(out);
	return out.toByteArray();
}

/**
 * Sets a flag to the supplied value
 * @see Flags
 */
public void
setFlag(int bit) {
	flags[bit] = true;
}

/**
 * Sets a flag to the supplied value
 * @see Flags
 */
public void
unsetFlag(int bit) {
	flags[bit] = false;
}

/**
 * Retrieves a flag
 * @see Flags
 */
public boolean
getFlag(int bit) {
	return flags[bit];
}

boolean []
getFlags() {
	return flags;
}

/**
 * Retrieves the message ID
 */
public int
getID() {
	return id & 0xFFFF;
}

/**
 * Sets the message ID
 */
public void
setID(int _id) {
	id = _id;
}

/**
 * Generates a random number suitable for use as a message ID
 */
static short
randomID() {
	Random random = new Random();
	return (short) (random.nextInt() & 0xFFFF);
}

/**
 * Sets the message's rcode
 * @see Rcode
 */
public void
setRcode(short value) {
	rcode = value;
}

/**
 * Retrieves the mesasge's rcode
 * @see Rcode
 */
public short
getRcode() {
	return rcode;
}

/**
 * Sets the message's opcode
 * @see Opcode
 */
public void
setOpcode(byte value) {
	opcode = value;
}

/**
 * Retrieves the mesasge's opcode
 * @see Opcode
 */
public byte
getOpcode() {
	return opcode;
}

void
setCount(int field, int value) {
	counts[field] = value;
}

void
incCount(int field) {
	counts[field]++;
}

void
decCount(int field) {
	counts[field]--;
}

/**
 * Retrieves the record count for the given section
 * @see Section
 */
public int
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

/** Converts the header's flags into a String */
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

String
toStringWithRcode(short newrcode) {
	StringBuffer sb = new StringBuffer();

	sb.append(";; ->>HEADER<<- "); 
	sb.append("opcode: " + Opcode.string(getOpcode()));
	sb.append(", status: " + Rcode.string(newrcode));
	sb.append(", id: " + getID());
	sb.append("\n");

	sb.append(";; flags: " + printFlags());
	sb.append("; ");
	for (int i = 0; i < 4; i++)
		sb.append(Section.string(i) + ": " + getCount(i) + " ");
	return sb.toString();
}

/** Converts the header into a String */
public String
toString() {
	return toStringWithRcode(getRcode());
}

/* Creates a new Header identical to the current one */
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
