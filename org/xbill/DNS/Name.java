// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

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
private static final int LABEL_EXTENDED = 0x40;
private static final int LABEL_MASK = 0xC0;

private static final int EXT_LABEL_BITSTRING = 1;

private Object [] name;
private byte offset;
private byte labels;
private boolean qualified;
private boolean hasBitString;
private int hashcode;

/** The root name */
public static final Name root = Name.fromConstantString(".");

/** The maximum number of labels in a Name */
static final int MAXLABELS = 128;

/* The number of labels initially allocated. */
private static final int STARTLABELS = 4;

/* Used for printing non-printable characters */
private static final DecimalFormat byteFormat = new DecimalFormat();

/* Used to efficiently convert bytes to lowercase */
private static final byte lowercase[] = new byte[256];

/* Used in wildcard names. */
private static final Name wildcardName = Name.fromConstantString("*");
private static final byte wildcardLabel[] = (byte []) wildcardName.name[0];

static {
	byteFormat.setMinimumIntegerDigits(3);
	for (int i = 0; i < lowercase.length; i++) {
		if (i < 'A' || i > 'Z')
			lowercase[i] = (byte)i;
		else
			lowercase[i] = (byte)(i - 'A' + 'a');
	}
}

private
Name() {
}

private final void
grow(int n) {
	if (n > MAXLABELS)
		throw new ArrayIndexOutOfBoundsException("name too long");
	Object [] newarray = new Object[n];
	System.arraycopy(name, 0, newarray, 0, labels);
	name = newarray;
}

private final void
grow() {
	grow(labels * 2);
}

private final void
compact() {
	for (int i = labels - 1 + offset; i > offset; i--) {
		if (!(name[i] instanceof BitString) ||
		    !(name[i - 1] instanceof BitString))
		    	continue;
		BitString bs = (BitString) name[i];
		BitString bs2 = (BitString) name[i - 1];
		if (bs.nbits == 256)
			continue;
		int nbits = bs.nbits + bs2.nbits;
		bs.join(bs2);
		if (nbits <= 256) {
			System.arraycopy(name, i, name, i - 1, labels - i);
			labels--;
		}
	}
}

/**
 * Create a new name from a string and an origin
 * @param s The string to be converted
 * @param origin If the name is unqualified, the origin to be appended
 * @deprecated As of dnsjava 1.3.0, replaced by <code>Name.fromString</code>.
 */
public
Name(String s, Name origin) {
	Name n;
	try {
		n = Name.fromString(s, origin);
	}
	catch (TextParseException e) {
		StringBuffer sb = new StringBuffer();
		sb.append(s);
		if (origin != null) {
			sb.append(".");
			sb.append(origin);
		}
		sb.append(": ");
		sb.append(e.getMessage());
		System.err.println(sb.toString());
		name = null;
		labels = 0;
		return;
	}
	labels = n.labels;
	name = n.name;
	qualified = n.qualified;
	if (!qualified) {
		/*
		 * This isn't exactly right, but it's close.
		 * Partially qualified names are evil.
		 */
		if (Options.check("pqdn"))
			qualified = false;
		else
			qualified = (labels > 1);
	}
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
 * @param origin If the name is unqualified, the origin to be appended.
 * @throws TextParseException The name is invalid.
 */
public static Name
fromString(String s, Name origin) throws TextParseException {
	Name name = new Name();
	name.labels = 0;
	name.name = new Object[1];

	if (s.equals("@")) {
		if (origin != null)
			return origin;
	} else if (s.equals(".")) {
		name.qualified = true;
		return name;
	}
	int labelstart = -1;
	int pos = 0;
	byte [] label = new byte[64];
	boolean escaped = false;
	int digits = 0;
	int intval = 0;
	boolean bitstring = false;
	for (int i = 0; i < s.length(); i++) {
		byte b = (byte) s.charAt(i);
		if (escaped) {
			if (pos == 0 && b == '[')
				bitstring = true;
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
			if (pos >= label.length)
				throw new TextParseException("label too long");
			label[pos++] = b;
			escaped = false;
		} else if (b == '\\') {
			escaped = true;
			digits = 0;
			intval = 0;
		} else if (b == '.') {
			if (labelstart == -1)
				throw new TextParseException("invalid label");
			byte [] newlabel = new byte[pos];
			System.arraycopy(label, 0, newlabel, 0, pos);
			if (name.labels == MAXLABELS)
				throw new TextParseException("too many labels");
			if (name.labels == name.name.length)
				name.grow();
			if (bitstring) {
				bitstring = false;
				name.name[name.labels++] =
						new BitString(newlabel);
				name.hasBitString = true;
			}
			else
				name.name[name.labels++] = newlabel;
			labelstart = -1;
			pos = 0;
		} else {
			if (labelstart == -1)
				labelstart = i;
			if (pos >= label.length)
				throw new TextParseException("label too long");
			label[pos++] = b;
		}
	}
	if (labelstart == -1)
		name.qualified = true;
	else {
		byte [] newlabel = new byte[pos];
		System.arraycopy(label, 0, newlabel, 0, pos);
		if (name.labels == MAXLABELS)
			throw new TextParseException("too many labels");
		if (name.labels == name.name.length)
			name.grow();
		if (bitstring) {
			bitstring = false;
			name.name[name.labels++] = new BitString(newlabel);
			name.hasBitString = true;
		}
		else
			name.name[name.labels++] = newlabel;
	}
	if (name.hasBitString)
		name.compact();
	if (origin != null)
		return concatenate(name, origin);
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
	int len, start, pos, count = 0, savedpos;
	Name name2;

	labels = 0;
	name = new Object[STARTLABELS];

	start = in.getPos();
loop:
	while ((len = in.readUnsignedByte()) != 0) {
		count++;
		switch(len & LABEL_MASK) {
		case LABEL_NORMAL:
			byte [] b = new byte[len];
			in.read(b);
			if (labels == name.length)
				grow();
			name[labels++] = b;
			break;
		case LABEL_COMPRESSION:
			pos = in.readUnsignedByte();
			pos += ((len & ~LABEL_MASK) << 8);
			if (Options.check("verbosecompression"))
				System.err.println("currently " + in.getPos() +
						   ", pointer to " + pos);
			if (pos >= in.getPos())
				throw new WireParseException("bad compression");
			savedpos = in.getPos();
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
			if (labels + name2.labels > name.length)
				grow(labels + name2.labels);
			System.arraycopy(name2.name, 0, name, labels,
					 name2.labels);
			labels += name2.labels;
			break loop;
		case LABEL_EXTENDED:
			int type = len & ~LABEL_MASK;
			switch (type) {
			case EXT_LABEL_BITSTRING:
				int bits = in.readUnsignedByte();
				if (bits == 0)
					bits = 256;
				int bytes = (bits + 7) / 8;
				byte [] data = new byte[bytes];
				in.read(data);
				if (labels == name.length)
					grow();
				name[labels++] = new BitString(bits, data);
				hasBitString = true;
				break;
			default:
				throw new WireParseException(
						"Unknown name format");
			} /* switch */
			break;
		} /* switch */
	}
	qualified = true;

	if (hasBitString)
		compact();
}

/**
 * Create a new name by removing labels from the beginning of an existing Name
 * @param src An existing Name
 * @param n The number of labels to remove from the beginning in the copy
 */
public
Name(Name src, int n) {
	name = src.name;
	offset = (byte)(src.offset + n);
	labels = (byte)(src.labels - n);
	qualified = src.qualified;
	if (!src.hasBitString)
		hasBitString = false;
	else {
		for (int i = 0; i < labels; i++)
			if (name[i + offset] instanceof BitString)
				hasBitString = true;
	}
}

/**
 * Creates a new name by concatenating two existing names.
 * @param prefix The prefix name.
 * @param suffix The suffix name.
 * @returns The concatenated name.
 */
public static Name
concatenate(Name prefix, Name suffix) {
	if (prefix.qualified)
		return (prefix);
	int nlabels = prefix.labels + suffix.labels;
	if (nlabels > MAXLABELS)
		return null;
	Name newname = new Name();
	newname.labels = (byte)nlabels;
	newname.name = new Object[nlabels];
	System.arraycopy(prefix.name, prefix.offset, newname.name,
			 0, prefix.labels);
	System.arraycopy(suffix.name, suffix.offset, newname.name,
			 prefix.labels, suffix.labels);
	newname.qualified = suffix.qualified;
	newname.hasBitString = (prefix.hasBitString || suffix.hasBitString);
	if (newname.hasBitString)
		newname.compact();
	return newname;
}

/**
 * Generates a new Name with the first n labels replaced by a wildcard 
 * @return The wildcard name
 */
public Name
wild(int n) {
	return concatenate(wildcardName, new Name(this, n));
}

/**
 * Generates a new Name to be used when following a DNAME.
 * @return The new name, or null if the DNAME is invalid.
 */
public Name
fromDNAME(DNAMERecord dname) {
	Name dnameowner = dname.getName();
	Name dnametarget = dname.getTarget();
	int nlabels;
	int saved;
	if (!subdomain(dnameowner))
		return null;
	saved = labels - dnameowner.labels;
	nlabels = saved + dnametarget.labels;
	if (nlabels > MAXLABELS)
		return null;
	Name newname = new Name();
	newname.labels = (byte)nlabels;
	newname.name = new Object[labels];
	System.arraycopy(this.name, 0, newname.name, 0, saved);
	System.arraycopy(dnametarget.name, 0, newname.name, saved,
			 dnametarget.labels);
	newname.qualified = true;
	for (int i = 0; i < newname.labels; i++)
		if (newname.name[i] instanceof BitString)
			newname.hasBitString = true;
	if (newname.hasBitString)
		newname.compact();
	return newname;
}

/**
 * Is this name a wildcard?
 */
public boolean
isWild() {
	if (labels == 0 || (name[0] instanceof BitString))
		return false;
	if (name[0] == wildcardLabel)
		return true;
	byte [] b = (byte []) name[0];
	return (b.length == 1 && b[0] == '*');
}

/**
 * Is this name fully qualified?
 */
public boolean
isQualified() {
	return qualified;
}

/**
 * The length of the name.
 */
public short
length() {
	short total = 0;
	for (int i = offset; i < labels + offset; i++) {
		if (name[i] instanceof BitString)
			total += (((BitString)name[i]).bytes() + 2);
		else
			total += (((byte [])name[i]).length + 1);
	}
	return ++total;
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
	Name tname = new Name(this, labels - domain.labels);
	return (tname.equals(domain));
}

private String
byteString(byte [] array) {
	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < array.length; i++) {
		/* Ick. */
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
	StringBuffer sb = new StringBuffer();
	if (labels == 0)
		sb.append(".");
	for (int i = offset; i < labels + offset; i++) {
		if (name[i] instanceof BitString)
			sb.append(name[i]);
		else
			sb.append(byteString((byte [])name[i]));
		if (qualified || i < labels - 1)
			sb.append(".");
	}
	return sb.toString();
}

/**
 * Convert the nth label in a Name to a String
 * @param n The label to be converted to a String
 */
public String
getLabelString(int n) {
	n += offset;
	if (name[n] instanceof BitString)
		return name[n].toString();
	else
		return byteString((byte [])name[n]);
}

/**
 * Convert Name to DNS wire format
 */
public void
toWire(DataByteOutputStream out, Compression c) throws IOException {
	for (int i = offset; i < labels + offset; i++) {
		Name tname;
		if (i == offset)
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
		}
		else {
			if (c != null)
				c.add(out.getPos(), tname);
			if (name[i] instanceof BitString) {
				out.writeByte(LABEL_EXTENDED |
					      EXT_LABEL_BITSTRING);
				out.writeByte(((BitString)name[i]).wireBits());
				out.write(((BitString)name[i]).data);
			}
			else
				out.writeString((byte []) name[i]);
		}
	}
	out.writeByte(0);
}

/**
 * Convert Name to canonical DNS wire format (all lowercase)
 */
public void
toWireCanonical(DataByteOutputStream out) throws IOException {
	for (int i = offset; i < labels + offset; i++) {
		if (name[i] instanceof BitString) {
			out.writeByte(LABEL_EXTENDED | EXT_LABEL_BITSTRING);
			out.writeByte(((BitString)name[i]).wireBits());
			out.write(((BitString)name[i]).data);
		}
		else {
			byte [] b = (byte []) name[i];
			byte [] bc = new byte[b.length];
			for (int j = 0; j < b.length; j++)
				bc[j] = lowercase[b[j]];
			out.writeString(bc);
		}
	}
	out.writeByte(0);
}

/**
 * Convert Name to canonical DNS wire format (all lowercase)
 */
public byte []
toWireCanonical() throws IOException {
	DataByteOutputStream out = new DataByteOutputStream();
	toWireCanonical(out);
	return out.toByteArray();
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
	for (int i = 0; i < labels; i++) {
		Object nobj = name[offset + i];
		Object dnobj = d.name[d.offset + i];
		if (nobj.getClass() != dnobj.getClass())
			return false;
		if (nobj instanceof BitString) {
			if (!nobj.equals(dnobj))
				return false;
		} else {
			byte [] b1 = (byte []) nobj;
			byte [] b2 = (byte []) dnobj;
			if (b1.length != b2.length)
				return false;
			for (int j = 0; j < b1.length; j++) {
				if (lowercase[b1[j]] != lowercase[b2[j]])
					return false;
			}
		}
	}
	return true;
}

/**
 * Computes a hashcode based on the value
 */
public int
hashCode() {
	if (hashcode != 0)
		return (hashcode);
	int code = labels;
	for (int i = offset; i < labels + offset; i++) {
		if (name[i] instanceof BitString) {
			BitString b = (BitString) name[i];
			for (int j = 0; j < b.bytes(); j++)
				code += ((code << 3) + b.data[j]);
		}
		else {
			byte [] b = (byte []) name[i];
			for (int j = 0; j < b.length; j++)
				code += ((code << 3) + lowercase[b[j]]);
		}
	}
	hashcode = code;
	return hashcode;
}

/**
 * Compares this Name to another Object.
 * @param The Object to be compared.
 * @return The value 0 if the argument is a name equivalent to this name;
 * a value less than 0 if the argument is less than this name in the canonical 
 * ordering, and a value greater than 0 if the argument is greater than this
 * name in the canonical ordering.
 * @throws ClassCastException if the argument is not a Name.
 */
public int
compareTo(Object o) {
	Name arg = (Name) o;

	int compares = labels > arg.labels ? arg.labels : labels;

	for (int i = 1; i <= compares; i++) {
		Object label = name[labels - i + offset];
		Object alabel = arg.name[arg.labels - i + arg.offset];

		if (label.getClass() != alabel.getClass()) {
			if (label instanceof BitString)
				return (-1);
			else
				return (1);
		}
		if (label instanceof BitString) {
			BitString bs = (BitString)label;
			BitString abs = (BitString)alabel;
			int bits = bs.nbits > abs.nbits ? abs.nbits : bs.nbits;
			int n = bs.compareBits(abs, bits);
			if (n != 0)
				return (n);
			if (bs.nbits == abs.nbits)
				continue;

			/*
			 * If label X has more bits than label Y, then the
			 * name with X is greater if Y is the first label
			 * of its name.  Otherwise, the name with Y is greater.
			 */
			if (bs.nbits > abs.nbits)
				return (i == arg.labels ? 1 : -1);
			else
				return (i == labels ? -1 : 1);
		}
		else {
			byte [] b = (byte []) label;
			byte [] ab = (byte []) alabel;
			for (int j = 0; j < b.length && j < ab.length; j++) {
				int n = lowercase[b[j]] - lowercase[ab[j]];
				if (n != 0)
					return (n);
			}
			if (b.length != ab.length)
				return (b.length - ab.length);
		}
	}
	return (labels - arg.labels);
}

}
