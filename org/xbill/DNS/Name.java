// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsName {

private String [] name;
private byte labels;

static final int MAXLABELS = 64;

dnsName(String s) {
	StringTokenizer st = new StringTokenizer(s, ".");

	labels = 0;
	name = new String[MAXLABELS];

	try {
		while (st.hasMoreTokens())
			name[labels++] = st.nextToken();
	}
	catch (ArrayIndexOutOfBoundsException e) {
		System.out.println("String " + s + " has too many labels");
		name = null;
		labels = 0;
	}
	
}

dnsName(CountedDataInputStream in, dnsCompression c) throws IOException {
	int len, start, count = 0;

	labels = 0;
	name = new String[MAXLABELS];

	start = in.getPos();
	while ((len = in.readUnsignedByte()) != 0) {
		if ((len & 0xC0) != 0) {
			int pos = in.readUnsignedByte();
			pos += ((len & ~0xC0) << 8);
			dnsName name2 = (c == null) ? null : c.get(pos);
/*System.out.println("Looking for compressed name at " + pos + ", found " + name2);*/
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
			dnsName tname = new dnsName(this, i);
			c.add(pos, tname);
/*System.out.println("Adding " + tname + " at " + pos);*/
			pos += (name[i].length() + 1);
		}
}

/* Skips n labels and creates a new name */
dnsName(dnsName d, int n) {
	name = new String[MAXLABELS];

	labels = (byte) (d.labels - n);
	System.arraycopy(d.name, n, name, 0, labels);
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

public String
toString() {
	StringBuffer sb = new StringBuffer();
	for (int i=0; i<labels; i++)
		sb.append(name[i] + ".");
	return sb.toString();
}

public void
toWire(DataOutputStream out) throws IOException {
	for (int i=0; i<labels; i++) {
		out.writeByte(name[i].length());
		for (int j=0; j<name[i].length(); j++)
			out.writeByte(name[i].charAt(j));
	}
	out.writeByte(0);
}

public void
toWireCanonical(DataOutputStream out) throws IOException {
	for (int i=0; i<labels; i++) {
		out.writeByte(name[i].length());
		for (int j=0; j<name[i].length(); j++)
			out.writeByte(Character.toLowerCase(name[i].charAt(j)));
	}
	out.writeByte(0);
}

public boolean
equals(Object arg) {
	if (arg == null || !(arg instanceof dnsName))
		return false;
	dnsName d = (dnsName) arg;
	if (d.labels != labels)
		return false;
	for (int i = 0; i < labels; i++) {
		if (!d.name[i].equalsIgnoreCase(name[i]))
			return false;
	}
	return true;
}

}
