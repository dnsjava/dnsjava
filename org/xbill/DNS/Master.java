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
private File file;
private Record last = null;
private long defaultTTL = -1;
private Master included = null;
private Tokenizer st;

Master(File file, Name defaultOrigin) throws IOException {
	FileInputStream fis;
	this.file = file;
	st = new Tokenizer(file);
	origin = defaultOrigin;
}

/** Begins parsing the specified file with an initial origin */
public
Master(String filename, Name origin) throws IOException {
	this(new File(filename), origin);
}

/** Begins parsing the specified file */
public
Master(String filename) throws IOException {
	this(new File(filename), null);
}

/** Begins parsing from an input stream with an initial origin */
public
Master(InputStream in, Name defaultOrigin) {
	st = new Tokenizer(in);
	origin = defaultOrigin;
}

/** Begins parsing from an input reader */
public
Master(InputStream in) {
	this(in, null);
}

private Name
parseName(String s, Name origin) throws TextParseException {
	try {
		return Name.fromString(s, origin);
	}
	catch (TextParseException e) {
		throw st.exception(e.getMessage());
	}
}

/** Returns the next record in the master file */
public Record
nextRecord() throws IOException {
	Tokenizer.Token token;
	String s;

	if (included != null) {
		Record rec = included.nextRecord();
		if (rec != null)
			return rec;
		included = null;
	}
	while (true) {
		Name name;
		int ttl;
		short type, dclass;

		token = st.get(true, false);
		if (token.type == Tokenizer.WHITESPACE) {
			if (last == null)
				throw st.exception("no owner");
			name = last.getName();
		}
		else if (token.type == Tokenizer.EOL)
			continue;
		else if (token.type == Tokenizer.EOF)
			return null;
		else {
			s = token.value;

			if (s.equals("$ORIGIN")) {
				origin = st.getName(Name.root);
				st.getEOL();
				continue;
			} else if (s.equals("$TTL")) {
				defaultTTL = st.getTTL();
				st.getEOL();
				continue;
			} else  if (s.equals("$INCLUDE")) {
				String filename = st.getString();
				String parent = file.getParent();
				File newfile = new File(file.getParent(),
							filename);
				Name incorigin = origin;
				token = st.get();
				if (token.isString()) {
					incorigin = parseName(token.value,
							      Name.root);
					st.getEOL();
				}
				included = new Master(newfile, incorigin);
				/*
				 * If we continued, we wouldn't be looking in
				 * the new file.  Recursing works better.
				 */
				return nextRecord();
			} else if (s.charAt(0) == '$') {
				throw st.exception("Invalid directive: " + s);
			} else {
				name = parseName(s, origin);
			}
		}

		s = st.getString();
		try {
			ttl = TTL.parseTTL(s);
			s = st.getString();
		}
		catch (NumberFormatException e) {
			if (last == null && defaultTTL < 0)
				throw st.exception("missing TTL");
			else if (defaultTTL >= 0)
				ttl = (int) defaultTTL;
			else
				ttl = last.getTTL();
		}

		if ((dclass = DClass.value(s)) > 0)
			s = st.getString();
		else
			dclass = DClass.IN;
		
		if ((type = Type.value(s)) < 0)
			throw st.exception("Invalid type '" + s + "'");

		last = Record.fromString(name, type, dclass, ttl, st, origin);
		st.getEOL();
		return last;
	}
}

}
