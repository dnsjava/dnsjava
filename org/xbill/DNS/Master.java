// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;

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
private long defaultTTL;
private Master included = null;
private Tokenizer st;

Master(File file, Name initialOrigin, long initialTTL) throws IOException {
	if (origin != null && !origin.isAbsolute()) {
		throw new RelativeNameException(origin);
	}
	this.file = file;
	st = new Tokenizer(file);
	origin = initialOrigin;
	defaultTTL = initialTTL;
}

/**
 * Initializes the master file reader and opens the specified master file.
 * @param filename The master file.
 * @param origin The initial origin to append to relative names.
 * @param ttl The initial default TTL.
 * @throws IOException The master file could not be opened.
 */
public
Master(String filename, Name origin, long ttl) throws IOException {
	this(new File(filename), origin, ttl);
}

/**
 * Initializes the master file reader and opens the specified master file.
 * @param filename The master file.
 * @param origin The initial origin to append to relative names.
 * @throws IOException The master file could not be opened.
 */
public
Master(String filename, Name origin) throws IOException {
	this(new File(filename), origin, -1);
}

/**
 * Initializes the master file reader and opens the specified master file.
 * @param filename The master file.
 * @throws IOException The master file could not be opened.
 */
public
Master(String filename) throws IOException {
	this(new File(filename), null, -1);
}

/**
 * Initializes the master file reader.
 * @param in The input stream containing a master file.
 * @param origin The initial origin to append to relative names.
 * @param ttl The initial default TTL.
 */
public
Master(InputStream in, Name origin, long ttl) {
	if (origin != null && !origin.isAbsolute()) {
		throw new RelativeNameException(origin);
	}
	st = new Tokenizer(in);
	this.origin = origin;
	defaultTTL = ttl;
}

/**
 * Initializes the master file reader.
 * @param in The input stream containing a master file.
 * @param origin The initial origin to append to relative names.
 */
public
Master(InputStream in, Name origin) {
	this(in, origin, -1);
}

/**
 * Initializes the master file reader.
 * @param in The input stream containing a master file.
 */
public
Master(InputStream in) {
	this(in, null, -1);
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

/**
 * Returns the next record in the master file.  This will process any
 * directives before the next record.
 * @return The next record.
 * @throws IOException The master file could not be read, or was syntactically
 * invalid.
 */
public Record
_nextRecord() throws IOException {
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
		long ttl;
		int type, dclass;
		boolean seen_class;

		token = st.get(true, false);
		if (token.type == Tokenizer.WHITESPACE) {
			Tokenizer.Token next = st.get();
			if (token.type == Tokenizer.EOL)
				continue;
			else if (token.type == Tokenizer.EOF)
				return null;
			else
				st.unget();
			if (last == null)
				throw st.exception("no owner");
			name = last.getName();
		}
		else if (token.type == Tokenizer.EOL)
			continue;
		else if (token.type == Tokenizer.EOF)
			return null;
		else if (((String) token.value).charAt(0) == '$') {
			s = token.value;

			if (s.equalsIgnoreCase("$ORIGIN")) {
				origin = st.getName(Name.root);
				st.getEOL();
				continue;
			} else if (s.equalsIgnoreCase("$TTL")) {
				defaultTTL = st.getTTL();
				st.getEOL();
				continue;
			} else  if (s.equalsIgnoreCase("$INCLUDE")) {
				String filename = st.getString();
				String parent = file.getParent();
				File newfile = new File(filename);
				Name incorigin = origin;
				token = st.get();
				if (token.isString()) {
					incorigin = parseName(token.value,
							      Name.root);
					st.getEOL();
				}
				included = new Master(newfile, incorigin,
						      defaultTTL);
				/*
				 * If we continued, we wouldn't be looking in
				 * the new file.  Recursing works better.
				 */
				return nextRecord();
			} else {
				throw st.exception("Invalid directive: " + s);
			}
		} else {
			s = token.value;
			name = parseName(s, origin);
			if (last != null && name.equals(last.getName())) {
				name = last.getName();
			}
		}

		// This is a bit messy, since any of the following are legal:
		//   class ttl type
		//   ttl class type
		//   class type
		//   ttl type
		//   type
		seen_class = false;
		s = st.getString();
		if ((dclass = DClass.value(s)) >= 0) {
			s = st.getString();
			seen_class = true;
		}

		try {
			ttl = TTL.parseTTL(s);
			s = st.getString();
		}
		catch (NumberFormatException e) {
			if (last == null && defaultTTL < 0)
				throw st.exception("missing TTL");
			else if (defaultTTL >= 0)
				ttl = defaultTTL;
			else
				ttl = last.getTTL();
		}

		if ((dclass = DClass.value(s)) >= 0) {
			s = st.getString();
		} else {
			dclass = DClass.IN;
		}

		if ((type = Type.value(s)) < 0)
			throw st.exception("Invalid type '" + s + "'");

		last = Record.fromString(name, type, dclass, ttl, st, origin);
		return last;
	}
}

/**
 * Returns the next record in the master file.  This will process any
 * directives before the next record.
 * @return The next record.
 * @throws IOException The master file could not be read, or was syntactically
 * invalid.
 */
public Record
nextRecord() throws IOException {
	Record rec = null;
	try {
		rec = _nextRecord();
	}
	finally {
		if (rec == null) {
			st.close();
		}
	}
	return rec;
}

protected void
finalize() {
	st.close();
}

}
