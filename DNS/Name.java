// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

/**
 * A representation of a domain name.
 */


public class Name {

private String [] name;
private byte labels;
private boolean qualified;

/** The root name */
public static Name root = new Name("");

/** The maximum number of labels in a Name */
static final int MAXLABELS = 64;

/**
 * Create a new name from a string and an origin
 * @param s  The string to be converted
 * @param origin  If the name is unqalified, the origin to be appended
 */
public
Name(String s, Name origin) {
	labels = 0;
	name = new String[MAXLABELS];

	if (s.equals("@") && origin != null) {
		append(origin);
		qualified = true;
		return;
	}
	try {
		MyStringTokenizer st = new MyStringTokenizer(s, ".");

		while (st.hasMoreTokens())
			name[labels++] = st.nextToken();

		if (st.hasMoreDelimiters())
			qualified = true;
		else {
			if (origin != null) {
				append(origin);
				qualified = true;
			}
			else {
				/* This isn't exactly right, but it's close.
				 * Partially qualified names are evil.
				 */
				qualified = (labels > 1);
			}
		}
	}
	catch (ArrayIndexOutOfBoundsException e) {
		StringBuffer sb = new StringBuffer();
		sb.append("String ");
		sb.append(s);
		if (origin != null) {
			sb.append(".");
			sb.append(origin);
		}
		sb.append(" has too many labels");
		System.out.println(sb.toString());
		name = null;
		labels = 0;
	}
	
}

/**
 * Create a new name from a string
 * @param s  The string to be converted
 */
public
Name(String s) {
	this (s, null);
}

Name(DataByteInputStream in, Compression c) throws IOException {
	int len, start, count = 0;

	labels = 0;
	name = new String[MAXLABELS];

	start = in.getPos();
	while ((len = in.readUnsignedByte()) != 0) {
		if ((len & 0xC0) != 0) {
			int pos = in.readUnsignedByte();
			pos += ((len & ~0xC0) << 8);
			Name name2 = (c == null) ? null : c.get(pos);
/*System.out.println("Looking for name at " + pos + ", found " + name2);*/
			if (name2 == null)
				name[labels++] = new String("<compressed>");
			else {
				System.arraycopy(name2.name, 0, name, labels,
						 name2.labels);
				labels += name2.labels;
			}
			break;
		}
		byte [] b = new byte[len];
		in.read(b);
		name[labels++] = new String(b);
		count++;
	}
	if (c != null) 
		for (int i = 0, pos = start; i < count; i++) {
			Name tname = new Name(this, i);
			c.add(pos, tname);
/*System.out.println("(D) Adding " + tname + " at " + pos);*/
			pos += (name[i].length() + 1);
		}
	qualified = true;
}

/**
 * Create a new name by removing labels from the beginning of an existing Name
 * @param d  An existing Name
 * @param n  The number of labels to remove from the beginning in the copy
 */
/* Skips n labels and creates a new name */
public
Name(Name d, int n) {
	name = new String[MAXLABELS];

	labels = (byte) (d.labels - n);
	System.arraycopy(d.name, n, name, 0, labels);
	qualified = d.qualified;
}

/**
 * Generates a new Name with the first label replaced by a wildcard 
 * @return The wildcard name
 */
public Name
wild() {
	Name wild = new Name(this, 0);
	wild.name[0] = "*";
	return wild;
}

/**
 * Is this name a wildcard?
 */
public boolean
isWild() {
	return name[0].equals("*");
}

/**
 * Is this name fully qualified?
 */
public boolean
isQualified() {
	return qualified;
}

/**
 * Appends the specified name to the end of the current Name
 */
public void
append(Name d) {
	System.arraycopy(d.name, 0, name, labels, d.labels);
	labels += d.labels;
}

/**
 * The length
 */
public short
length() {
	short total = 0;
	for (int i = 0; i < labels; i++)
		total += (name[i].length() + 1);
	return ++total;
}

/**
 * The number of labels
 */
public byte
labels() {
	return labels;
}

/**
 * Is the current Name a subdomain of the specified name?
 */
public boolean
subdomain(Name domain) {
	if (domain == null || domain.labels > labels)
		return false;
	int i = labels, j = domain.labels;
	while (j > 0)
		if (!name[--i].equals(domain.name[--j]))
			return false;
	return true;
}

/**
 * Convert Name to a String
 */
public String
toString() {
	StringBuffer sb = new StringBuffer();
	if (labels == 0)
		sb.append(".");
	for (int i=0; i<labels; i++) {
		sb.append(name[i]);
		if (qualified || i < labels - 1)
			sb.append(".");
	}
	return sb.toString();
}

/**
 * Convert Name to DNS wire format
 */
public void
toWire(DataByteOutputStream out, Compression c) throws IOException {
	for (int i=0; i<labels; i++) {
		Name tname = new Name(this, i);
		int pos;
		if (c != null)
			pos = c.get(tname);
		else
			pos = -1;
/*System.out.println("Looking for compressed " + tname + ", found " + pos);*/
		if (pos >= 0) {
			pos |= (0xC0 << 8);
			out.writeShort(pos);
			return;
		}
		else {
			if (c != null)
				c.add(out.getPos(), tname);
/*System.out.println("(C) Adding " + tname + " at " + out.getPos());*/
			out.writeString(name[i]);
		}
	}
	out.writeByte(0);
}

/**
 * Convert Name to canonical DNS wire format (all lowercase)
 */
public void
toWireCanonical(DataByteOutputStream out) throws IOException {
	for (int i=0; i<labels; i++) {
		out.writeByte(name[i].length());
		for (int j=0; j<name[i].length(); j++)
			out.writeByte(Character.toLowerCase(name[i].charAt(j)));
	}
	out.writeByte(0);
}

/**
 * Are these two Names equivalent?
 */
public boolean
equals(Object arg) {
	if (arg == null || !(arg instanceof Name))
		return false;
	Name d = (Name) arg;
	if (d.labels != labels)
		return false;
	for (int i = 0; i < labels; i++) {
		if (!d.name[i].equalsIgnoreCase(name[i]))
			return false;
	}
	return true;
}

/**
 * Computes a hashcode based on the value
 */
public int
hashCode() {
	int code = labels;
	for (int i = 0; i < labels; i++) {
		for (int j = 0; j < name[i].length(); j++)
			code += Character.toLowerCase(name[i].charAt(j));
	}
	return code;
}

}
