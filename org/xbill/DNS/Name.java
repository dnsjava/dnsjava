// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.text.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * A representation of a domain name. 
 *
 * @author Brian Wellington
 */

public class Name implements Comparable {

private static final int LABEL_NORMAL = 0;
private static final int LABEL_COMPRESSION = 0xC0;
private static final int LABEL_MASK = 0xC0;

private byte [] name;
private byte labels;
private int offsets;
private int hashcode;

private static final byte [] emptyLabel = new byte[] {(byte)0};
private static final byte [] wildLabel = new byte[] {(byte)1, (byte)'*'};

/** The root name */
public static final Name root;

/** The maximum length of a Name */
private static final int MAXNAME = 255;

/** The maximum length of labels a label a Name */
private static final int MAXLABEL = 63;

/** The maximum number of labels in a Name */
private static final int MAXLABELS = 128;

/** The maximum number of cached offsets */
private static final int MAXOFFSETS = 8;

/* Used for printing non-printable characters */
private static final DecimalFormat byteFormat = new DecimalFormat();

/* Used to efficiently convert bytes to lowercase */
private static final byte lowercase[] = new byte[256];

/* Used in wildcard names. */
private static final Name wild;

static {
	byteFormat.setMinimumIntegerDigits(3);
	for (int i = 0; i < lowercase.length; i++) {
		if (i < 'A' || i > 'Z')
			lowercase[i] = (byte)i;
		else
			lowercase[i] = (byte)(i - 'A' + 'a');
	}
	root = new Name();
	wild = new Name();
	root.appendSafe(emptyLabel, 1);
	wild.appendSafe(wildLabel, 1);
}

private
Name() {
}

private final void
dump(String prefix) {
	String s;
	try {
		s = toString();
	} catch (Exception e) {
		s = "<unprintable>";
	}
	System.out.println(prefix + ": " + s);

	for (int i = 0; i < labels; i++)
		System.out.print(offset(i) + " ");
	System.out.println("");

	for (int i = 0; i < name.length; i++)
		System.out.print((name[i] & 0xFF) + " ");
	System.out.println("");
}

private final void
setoffset(int n, int offset) {
	if (n >= MAXOFFSETS)
		return;
	int shift = 8 * (7 - n);
	offsets &= (~(0xFFL << shift));
	offsets |= ((long)offset << shift);
}

private final int
offset(int n) {
	if (n < MAXOFFSETS) {
		int shift = 8 * (7 - n);
		return ((int)(offsets >>> shift) & 0xFF);
	} else {
		int pos = offset(MAXOFFSETS - 1);
		for (int i = MAXOFFSETS - 1; i < n; i++)
			pos += (name[pos] + 1);
		return (pos);
	}
}

private static final void
copy(Name src, Name dst) {
	dst.name = src.name;
	dst.labels = src.labels;
	dst.offsets = src.offsets;
}

private final void
append(byte [] array, int n) throws NameTooLongException {
	int length = (name == null ? 0 : (name.length - offset(0)));
	int alength = 0;
	for (int i = 0, pos = 0; i < n; i++) {
		int len = array[pos];
		if (len > MAXLABEL)
			throw new IllegalStateException("invalid label");
		len++;
		pos += len;
		alength += len;
	}
	int newlength = length + alength;
	if (newlength > MAXNAME)
		throw new NameTooLongException();
	int newlabels = labels + n;
	if (newlabels > MAXLABELS)
		throw new IllegalStateException("too many labels");
	byte [] newname = new byte[newlength];
	if (length != 0)
		System.arraycopy(name, offset(0), newname, 0, length);
	System.arraycopy(array, 0, newname, length, alength);
	name = newname;
	for (int i = 0, pos = length; i < n; i++) {
		setoffset(labels + i, pos);
		pos += (newname[pos] + 1);
	}
	labels = (byte) newlabels;
}

private final void
appendFromString(byte [] array, int n) throws TextParseException {
	try {
		append(array, n);
	}
	catch (NameTooLongException e) {
		throw new TextParseException("Name too long");
	}
}

private final void
appendSafe(byte [] array, int n) {
	try {
		append(array, n);
	}
	catch (NameTooLongException e) {
	}
}

/**
 * Create a new name from a string and an origin
 * @param s The string to be converted
 * @param origin If the name is not absolute, the origin to be appended
 * @deprecated As of dnsjava 1.3.0, replaced by <code>Name.fromString</code>.
 */
public
Name(String s, Name origin) {
	Name n;
	try {
		n = Name.fromString(s, origin);
	}
	catch (TextParseException e) {
		StringBuffer sb = new StringBuffer(s);
		if (origin != null)
			sb.append("." + origin);
		sb.append(": "+ e.getMessage());
		System.err.println(sb.toString());
		return;
	}
	if (!n.isAbsolute() && !Options.check("pqdn") &&
	    n.labels > 1 && n.labels < MAXLABELS - 1)
	{
		/*
		 * This isn't exactly right, but it's close.
		 * Partially qualified names are evil.
		 */
		n.appendSafe(emptyLabel, 1);
	}
	copy(n, this);
}

/**
 * Create a new name from a string
 * @param s The string to be converted
 * @deprecated as of dnsjava 1.3.0, replaced by <code>Name.fromString</code>.
 */
public
Name(String s) {
	this (s, null);
}

/**
 * Create a new name from a string and an origin.  This does not automatically
 * make the name absolute; it will be absolute if it has a trailing dot or an
 * absolute origin is appended.
 * @param s The string to be converted
 * @param origin If the name is not absolute, the origin to be appended.
 * @throws TextParseException The name is invalid.
 */
public static Name
fromString(String s, Name origin) throws TextParseException {
	Name name = new Name();

	if (s.equals(""))
		throw new TextParseException("empty name");
	else if (s.equals("@")) {
		if (origin == null)
			return name;
		return origin;
	} else if (s.equals("."))
		return (root);
	int labelstart = -1;
	int pos = 1;
	byte [] label = new byte[MAXLABEL + 1];
	boolean escaped = false;
	int digits = 0;
	int intval = 0;
	boolean absolute = false;
	for (int i = 0; i < s.length(); i++) {
		byte b = (byte) s.charAt(i);
		if (escaped) {
			if (b >= '0' && b <= '9' && digits < 3) {
				digits++;
				intval *= 10 + (b - '0');
				intval += (b - '0');
				if (digits < 3)
					continue;
				b = (byte) intval;
			}
			else if (digits > 0 && digits < 3)
				throw new TextParseException("bad escape");
			if (pos >= MAXLABEL)
				throw new TextParseException("label too long");
			labelstart = pos;
			label[pos++] = b;
			escaped = false;
		} else if (b == '\\') {
			escaped = true;
			digits = 0;
			intval = 0;
		} else if (b == '.') {
			if (labelstart == -1)
				throw new TextParseException("invalid label");
			label[0] = (byte)(pos - 1);
			name.appendFromString(label, 1);
			labelstart = -1;
			pos = 1;
		} else {
			if (labelstart == -1)
				labelstart = i;
			if (pos >= MAXLABEL)
				throw new TextParseException("label too long");
			label[pos++] = b;
		}
	}
	if (labelstart == -1) {
		name.appendFromString(emptyLabel, 1);
		absolute = true;
	} else {
		label[0] = (byte)(pos - 1);
		name.appendFromString(label, 1);
	}
	if (origin != null && !absolute)
		name.appendFromString(origin.name, origin.labels);
	return (name);
}

/**
 * Create a new name from a string.  This does not automatically make the name
 * absolute; it will be absolute if it has a trailing dot.
 * @param s The string to be converted
 * @throws TextParseException The name is invalid.
 */
public static Name
fromString(String s) throws TextParseException {
	return fromString(s, null);
}

/**
 * Create a new name from a constant string.  This should only be used when
 the name is known to be good - that is, when it is constant.
 * @param s The string to be converted
 * @throws IllegalArgumentException The name is invalid.
 */
public static Name
fromConstantString(String s) {
	try {
		return fromString(s, null);
	}
	catch (TextParseException e) {
		throw new IllegalArgumentException("Invalid name '" + s + "'");
	}
}

/**
 * Create a new name from DNS wire format
 * @param in A stream containing the input data
 */
public
Name(DataByteInputStream in) throws IOException {
	int len, pos, savedpos;
	Name name2;
	boolean done = false;
	byte [] label = new byte[MAXLABEL + 1];

	while (!done) {
		len = in.readUnsignedByte();
		switch (len & LABEL_MASK) {
		case LABEL_NORMAL:
			if (labels >= MAXLABELS)
				throw new WireParseException("too many labels");
			if (len == 0) {
				append(emptyLabel, 1);
				done = true;
			} else {
				label[0] = (byte)len;
				in.readArray(label, 1, len);
				append(label, 1);
			}
			break;
		case LABEL_COMPRESSION:
			pos = in.readUnsignedByte();
			pos += ((len & ~LABEL_MASK) << 8);
			if (Options.check("verbosecompression"))
				System.err.println("currently " + in.getPos() +
						   ", pointer to " + pos);
			savedpos = in.getPos();
			if (pos >= savedpos)
				throw new WireParseException("bad compression");
			in.setPos(pos);
			if (Options.check("verbosecompression"))
				System.err.println("current name '" + this +
						   "', seeking to " + pos);
			try {
				name2 = new Name(in);
			}
			finally {
				in.setPos(savedpos);
			}
			append(name2.name, name2.labels);
			done = true;
			break;
		}
	}
}

/**
 * Create a new name by removing labels from the beginning of an existing Name
 * @param src An existing Name
 * @param n The number of labels to remove from the beginning in the copy
 */
public
Name(Name src, int n) {
	if (n > src.labels)
		throw new IllegalArgumentException("attempted to remove too " +
						   "many labels");
	name = src.name;
	labels = (byte)(src.labels - n);
	for (int i = 0; i < MAXOFFSETS && i < src.labels - n; i++)
		setoffset(i, src.offset(i + n));
}

/**
 * Creates a new name by concatenating two existing names.
 * @param prefix The prefix name.
 * @param suffix The suffix name.
 * @return The concatenated name.
 * @throws NameTooLongException The name is too long.
 */
public static Name
concatenate(Name prefix, Name suffix) throws NameTooLongException {
	if (prefix.isAbsolute())
		return (prefix);
	Name newname = new Name();
	copy(prefix, newname);
	newname.append(suffix.name, suffix.labels);
	return newname;
}

/**
 * Generates a new Name with the first n labels replaced by a wildcard 
 * @return The wildcard name
 */
public Name
wild(int n) {
	if (n < 1)
		throw new IllegalArgumentException("must replace 1 or more " +
						   "labels");
	try {
		return concatenate(wild, new Name(this, n));
	}
	catch (NameTooLongException e) {
		throw new IllegalStateException
					("Name.wild: concatenate failed");
	}
}

/**
 * Generates a new Name to be used when following a DNAME.
 * @param dname The DNAME record to follow.
 * @return The constructed name.
 * @throws NameTooLongException The resulting name is too long.
 */
public Name
fromDNAME(DNAMERecord dname) throws NameTooLongException {
	Name dnameowner = dname.getName();
	Name dnametarget = dname.getTarget();
	if (!subdomain(dnameowner))
		return null;

	int plabels = labels - dnameowner.labels;
	int plength = length() - dnameowner.length();
	int pstart = offset(0);

	int dlabels = dnametarget.labels;
	int dlength = dnametarget.length();

	if (plength + dlength > MAXNAME)
		throw new NameTooLongException();

	Name newname = new Name();
	newname.labels = (byte)(plabels + dlabels);
	newname.name = new byte[plength + dlength];
	System.arraycopy(name, pstart, newname.name, 0, plength);
	System.arraycopy(dnametarget.name, 0, newname.name, plength, dlength);

	for (int i = 0, pos = 0; i < MAXOFFSETS && i < newname.labels; i++) {
		newname.setoffset(i, pos);
		pos += (newname.name[pos] + 1);
	}
	return newname;
}

/**
 * Is this name a wildcard?
 */
public boolean
isWild() {
	if (labels == 0)
		return false;
	return (name[0] == (byte)1 && name[1] == (byte)'*');
}

/**
 * Is this name fully qualified (that is, absolute)?
 * @deprecated As of dnsjava 1.3.0, replaced by <code>isAbsolute</code>.
 */
public boolean
isQualified() {
	return (isAbsolute());
}

/**
 * Is this name absolute?
 */
public boolean
isAbsolute() {
	if (labels == 0)
		return false;
	return (name[name.length - 1] == 0);
}

/**
 * The length of the name.
 */
public short
length() {
	return (short)(name.length - offset(0));
}

/**
 * The number of labels in the name.
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
	if (domain.labels == labels)
		return equals(domain);
	return domain.equals(name, offset(labels - domain.labels));
}

private String
byteString(byte [] array, int pos) {
	StringBuffer sb = new StringBuffer();
	int len = array[pos++];
	for (int i = pos; i < pos + len; i++) {
		short b = (short)(array[i] & 0xFF);
		if (b <= 0x20 || b >= 0x7f) {
			sb.append('\\');
			sb.append(byteFormat.format(b));
		}
		else if (b == '"' || b == '(' || b == ')' || b == '.' ||
			 b == ';' || b == '\\' || b == '@' || b == '$')
		{
			sb.append('\\');
			sb.append((char)b);
		}
		else
			sb.append((char)b);
	}
	return sb.toString();
}

/**
 * Convert Name to a String
 */
public String
toString() {
	if (labels == 0)
		return "@";
	else if (labels == 1 && name[offset(0)] == 0)
		return ".";
	StringBuffer sb = new StringBuffer();
	for (int i = 0, pos = offset(0); i < labels; i++) {
		int len = name[pos];
		if (len > MAXLABEL)
			throw new IllegalStateException("invalid label");
		if (len == 0)
			break;
		sb.append(byteString(name, pos));
		sb.append('.');
		pos += (1 + len);
	}
	return sb.toString();
}

/**
 * Convert the nth label in a Name to a String
 * @param n The label to be converted to a String
 */
public String
getLabelString(int n) {
	int pos = offset(n);
	return byteString(name, pos);
}

/**
 * Convert Name to DNS wire format
 * @param out The output stream containing the DNS message.
 * @param c The compression context, or null of no compression is desired.
 * @throws IOException An error occurred writing the name.
 * @throws IllegalArgumentException The name is not absolute.
 */
public void
toWire(DataByteOutputStream out, Compression c) throws IOException {
	if (!isAbsolute())
		throw new IllegalArgumentException("toWire() called on " +
						   "non-absolute name");
	
	for (int i = 0; i < labels - 1; i++) {
		Name tname;
		if (i == 0)
			tname = this;
		else
			tname = new Name(this, i);
		int pos = -1;
		if (c != null)
			pos = c.get(tname);
		if (pos >= 0) {
			pos |= (LABEL_MASK << 8);
			out.writeShort(pos);
			return;
		} else {
			if (c != null)
				c.add(out.getPos(), tname);
			out.writeString(name, offset(i));
		}
	}
	out.writeByte(0);
}

/**
 * Convert Name to canonical DNS wire format (all lowercase)
 * @param out The output stream to which the message is written.
 * @throws IOException An error occurred writing the name.
 */
public void
toWireCanonical(DataByteOutputStream out) throws IOException {
	byte [] b = toWireCanonical();
	out.write(b);
}

/**
 * Convert Name to canonical DNS wire format (all lowercase)
 * @throws IOException An error occurred writing the name.
 */
public byte []
toWireCanonical() throws IOException {
	if (labels == 0)
		return (new byte[0]);
	byte [] b = new byte[name.length - offset(0)];
	for (int i = 0, pos = offset(0); i < labels; i++) {
		int len = name[pos];
		if (len > MAXLABEL)
			throw new IllegalStateException("invalid label");
		b[pos] = name[pos++];
		for (int j = 0; j < len; j++)
			b[pos] = lowercase[name[pos++]];
	}
	return b;
}

private final boolean
equals(byte [] b, int bpos) {
	for (int i = 0, pos = offset(0); i < labels; i++) {
		if (name[pos] != b[bpos])
			return false;
		int len = name[pos++];
		bpos++;
		if (len > MAXLABEL)
			throw new IllegalStateException("invalid label");
		for (int j = 0; j < len; j++)
			if (lowercase[name[pos++]] != lowercase[b[bpos++]])
				return false;
	}
	return true;
}

/**
 * Are these two Names equivalent?
 */
public boolean
equals(Object arg) {
	if (arg == this)
		return true;
	if (arg == null || !(arg instanceof Name))
		return false;
	Name d = (Name) arg;
	if (d.labels != labels)
		return false;
	return equals(d.name, d.offset(0));
}

/**
 * Computes a hashcode based on the value
 */
public int
hashCode() {
	if (hashcode != 0)
		return (hashcode);
	int code = labels;
	for (int i = offset(0); i < name.length; i++)
		code += ((code << 3) + lowercase[name[i]]);
	hashcode = code;
	return hashcode;
}

/**
 * Compares this Name to another Object.
 * @param o The Object to be compared.
 * @return The value 0 if the argument is a name equivalent to this name;
 * a value less than 0 if the argument is less than this name in the canonical 
 * ordering, and a value greater than 0 if the argument is greater than this
 * name in the canonical ordering.
 * @throws ClassCastException if the argument is not a Name.
 */
public int
compareTo(Object o) {
	Name arg = (Name) o;

	if (this == arg)
		return (0);

	int compares = labels > arg.labels ? arg.labels : labels;

	for (int i = 1; i <= compares; i++) {
		int start = offset(labels - i);
		int astart = arg.offset(arg.labels - i);
		int length = name[start];
		int alength = arg.name[astart];
		for (int j = 0; j < length && j < alength; j++) {
			int n = lowercase[name[j + start]] -
				lowercase[arg.name[j + astart]];
			if (n != 0)
				return (n);
		}
		if (length != alength)
			return (length - alength);
	}
	return (labels - arg.labels);
}

}
