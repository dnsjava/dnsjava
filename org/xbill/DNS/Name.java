// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class Name {

private String [] name;
private byte labels;

public static Name root = new Name("");

static final int MAXLABELS = 64;

public
Name(String s, Name origin) {
	labels = 0;
	name = new String[MAXLABELS];

	if (s.equals("@") && origin != null) {
		append(origin);
		return;
	}
	try {
		MyStringTokenizer st = new MyStringTokenizer(s, ".");

		while (st.hasMoreTokens())
			name[labels++] = st.nextToken();

		if (!st.hasMoreDelimiters() && origin != null)
			append(origin);
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
}

/* Skips n labels and creates a new name */
public
Name(Name d, int n) {
	name = new String[MAXLABELS];

	labels = (byte) (d.labels - n);
	System.arraycopy(d.name, n, name, 0, labels);
}

public void
append(Name d) {
	System.arraycopy(d.name, 0, name, labels, d.labels);
	labels += d.labels;
}

public short
length() {
	short total = 0;
	for (int i = 0; i < labels; i++)
		total += (name[i].length() + 1);
	return ++total;
}

public byte
labels() {
	return labels;
}

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

public String
toString() {
	StringBuffer sb = new StringBuffer();
	if (labels == 0)
		sb.append(".");
	for (int i=0; i<labels; i++)
		sb.append(name[i] + ".");
	return sb.toString();
}

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

public void
toWireCanonical(DataByteOutputStream out) throws IOException {
	for (int i=0; i<labels; i++) {
		out.writeByte(name[i].length());
		for (int j=0; j<name[i].length(); j++)
			out.writeByte(Character.toLowerCase(name[i].charAt(j)));
	}
	out.writeByte(0);
}

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

public int
hashCode() {
	int code = labels;
	for (int i = 0; i < labels; i++) {
		for (int j = 0; j < name[i].length(); j++)
			code += name[i].charAt(j);
	}
	return code;
}

}
