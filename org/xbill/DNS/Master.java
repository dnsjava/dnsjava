// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;
import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * A DNS master file parser.  This incrementally parses the file, returning
 * one record at a time.  When directives are seen, they are added to the
 * state and used when parsing future records.
 *
 * @author Brian Wellington
 */

public class Master {

private Name origin;
private BufferedReader br;
private File file;
private Record last = null;
private int defaultTTL = 3600;
private Master included = null;

Master(File _file, Name defaultOrigin) throws IOException {
	FileInputStream fis;
	file = _file;
	try {
		fis = new FileInputStream(file);
	}
	catch (FileNotFoundException e) {
		throw new IOException(e.toString());
	}
	br = new BufferedReader(new InputStreamReader(fis));
	origin = defaultOrigin;
}

/** Begins parsing the specified file */
public
Master(String filename) throws IOException {
	this(new File(filename), null);
}

/** Returns the next record in the master file */
public Record
nextRecord() throws IOException {
	String line;
	MyStringTokenizer st;

	if (included != null) {
		Record rec = included.nextRecord();
		if (rec != null)
			return rec;
		included = null;
	}
	while (true) {
		line = readExtendedLine(br);
		if (line == null)
			return null;
		if (line.length() == 0 || line.startsWith(";"))
			continue;

		boolean space = line.startsWith(" ") || line.startsWith("\t");
		st = new MyStringTokenizer(line);

		String s = st.nextToken();
		if (s.equals("$ORIGIN")) {
			origin = parseOrigin(st);
			continue;
		}
		if (s.equals("$TTL")) {
			defaultTTL = parseTTL(st);
			continue;
		}
		if (s.equals("$INCLUDE")) {
			parseInclude(st);
			/*
			 * If we continued, we wouldn't be looking in
			 * the new file.  Recursing works better.
			 */
			return nextRecord();
		}
		else if (s.charAt(0) == '$')
			throw new IOException("Invalid directive: " + s);
		st.putBackToken(s);
		return (last = parseRR(st, space, last, origin));
	}
}

private Name
parseOrigin(MyStringTokenizer st) throws IOException {
	if (!st.hasMoreTokens())
		throw new IOException ("Missing ORIGIN");
	return new Name(st.nextToken());
}

private int
parseTTL(MyStringTokenizer st) throws IOException {
	if (!st.hasMoreTokens())
		throw new IOException ("Missing TTL");
	return Integer.parseInt(st.nextToken());
}

private void
parseInclude(MyStringTokenizer st) throws IOException {
	if (!st.hasMoreTokens())
		throw new IOException ("Missing file to include");
	File newfile;
	String filename = st.nextToken();
	if (file.getParent() == null)
		newfile = new File(filename);
	else
		newfile = new File(file.getParent(), filename);
	if (st.hasMoreTokens())
		included = new Master(newfile, new Name(st.nextToken()));
	else
		included = new Master(newfile, origin);
}

private Record
parseRR(MyStringTokenizer st, boolean useLast, Record last, Name origin)
throws IOException
{
	Name name;
	int ttl;
	short type, dclass;

	if (!useLast)
		name = new Name(st.nextToken(), origin);
	else
		name = last.getName();

	String s = st.nextToken();

	try {
		ttl = TTL.parseTTL(s);
		s = st.nextToken();
	}
	catch (NumberFormatException e) {
		if (!useLast || last == null)
			ttl = defaultTTL;
		else
			ttl = last.getTTL();
	}

	if ((dclass = DClass.value(s)) > 0)
		s = st.nextToken();
	else
		dclass = DClass.IN;
		

	if ((type = Type.value(s)) < 0)
		throw new IOException("Parse error");

	return Record.fromString(name, type, dclass, ttl, st, origin);
}

private static String
stripTrailing(String s) {
	if (s == null)
		return null;
	int lastChar;
	int semi;
	if ((semi = s.lastIndexOf(';')) < 0)
		lastChar = s.length() - 1;
	else
		lastChar = semi - 1;
	for (int i = lastChar; i >= 0; i--) {
		if (!Character.isWhitespace(s.charAt(i)))
			return s.substring(0, i+1);
	}
	return "";
}

/**
 * Reads a line using the master file format.  Removes all data following
 * a semicolon and uses parentheses as line continuation markers.
 * @param br The BufferedReader supplying the data
 * @return A String representing the normalized line
 */
public static String
readExtendedLine(BufferedReader br) throws IOException {
	String s = stripTrailing(br.readLine());
	if (s == null)
		return null;
	if (!s.endsWith("("))
		return s;
	StringBuffer sb = new StringBuffer(s.substring(0, s.length() - 1));
	while (true) {
		s = stripTrailing(br.readLine().trim());
		if (s == null)
			return sb.toString();
		sb.append(" ");
		if (s.endsWith(")")) {
			sb.append(s.substring(0, s.length() - 1));
			break;
		}
		else
			sb.append(s);
	}
	return sb.toString();
}

}
