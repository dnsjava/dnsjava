// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

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
private int rcode;
private int opcode;
private int [] counts;

private static Random random = new Random();

/** The length of a DNS Header in wire format. */
public static final int LENGTH = 12;

/**
 * Create a new empty header.
 * @param id The message id
 */
public
Header(int id) {
	counts = new int[4];
	flags = new boolean[16];
	this.id = id;
}

/**
 * Create a new empty header with a random message id
 */
public
Header() {
	this(random.nextInt(0xffff));
}

/**
 * Parses a Header from a stream containing DNS wire format.
 */
Header(DNSInput in) throws IOException {
	this(in.readU16());
	readFlags(in);
	for (int i = 0; i < counts.length; i++)
		counts[i] = in.readU16();
}

/**
 * Creates a new Header from its DNS wire format representation
 * @param b A byte array containing the DNS Header.
 */
public
Header(byte [] b) throws IOException {
	this(new DNSInput(b));
}

void
toWire(DNSOutput out) {
	out.writeU16(getID());
	writeFlags(out);
	for (int i = 0; i < counts.length; i++)
		out.writeU16(counts[i]);
}

public byte []
toWire() {
	DNSOutput out = new DNSOutput();
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
setID(int id) {
	if (opcode > 0xFF)
		throw new IllegalArgumentException("DNS message ID " + id +
						   "is out of range");
	this.id = id;
}

/**
 * Generates a random number suitable for use as a message ID
 */
static int
randomID() {
	return (random.nextInt(0xffff));
}

/**
 * Sets the message's rcode
 * @see Rcode
 */
public void
setRcode(int value) {
	if (opcode > 0xF)
		throw new IllegalArgumentException("DNS Rcode " + value +
						   "is out of range");
	rcode = value;
}

/**
 * Retrieves the mesasge's rcode
 * @see Rcode
 */
public int
getRcode() {
	return rcode;
}

/**
 * Sets the message's opcode
 * @see Opcode
 */
public void
setOpcode(int value) {
	if (opcode > 0xF)
		throw new IllegalArgumentException("DNS Opcode " + value +
						   "is out of range");
	opcode = value;
}

/**
 * Retrieves the mesasge's opcode
 * @see Opcode
 */
public int
getOpcode() {
	return opcode;
}

void
setCount(int field, int value) {
	if (value > 0xFF)
		throw new IllegalArgumentException("DNS section count " +
						   value +
						   "is out of range");
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
writeFlags(DNSOutput out) {
	int flagsval = 0;
	for (int i = 0; i < 16; i++) {
		if (flags[i])
			flagsval |= (1 << (15-i));
	}
	flagsval |= (opcode << 11);
	flagsval |= (rcode);
	out.writeU16(flagsval);
}

private void
readFlags(DNSInput in) throws IOException {
	int flagsval = in.readU16();
	for (int i = 0; i < 16; i++) {
		flags[i] = ((flagsval & (1 << (15 - i))) != 0);
	}
	opcode = (byte) ((flagsval >> 11) & 0xF);
	rcode = (byte) (flagsval & 0xF);
}

/** Converts the header's flags into a String */
public String
printFlags() {
	StringBuffer sb = new StringBuffer();

	for (int i = 0; i < flags.length; i++)
		if (Flags.isFlag(i) && getFlag(i)) {
			sb.append(Flags.string(i));
			sb.append(" ");
		}
	return sb.toString();
}

String
toStringWithRcode(int newrcode) {
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
	Header h = new Header(id);
	System.arraycopy(counts, 0, h.counts, 0, counts.length);
	System.arraycopy(flags, 0, h.flags, 0, flags.length);
	h.rcode = rcode;
	h.rcode = rcode;
	h.opcode = opcode;
	return h;
}

}
