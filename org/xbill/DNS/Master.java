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
private int currentType;
private int currentDClass;
private long currentTTL;

private boolean generating;
private String genNameSpec;
private String genRdataSpec;
private long genStart;
private long genEnd;
private long genStep;
private long genCurrent;

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

private void
parseTTLClassAndType() throws IOException {
	String s;
	boolean seen_class = false;


	// This is a bit messy, since any of the following are legal:
	//   class ttl type
	//   ttl class type
	//   class type
	//   ttl type
	//   type
	seen_class = false;
	s = st.getString();
	if ((currentDClass = DClass.value(s)) >= 0) {
		s = st.getString();
		seen_class = true;
	}

	try {
		currentTTL = TTL.parseTTL(s);
		s = st.getString();
	}
	catch (NumberFormatException e) {
		if (last == null && defaultTTL < 0)
			throw st.exception("missing TTL");
		else if (defaultTTL >= 0)
			currentTTL = defaultTTL;
		else
			currentTTL = last.getTTL();
	}

	if (!seen_class) {
		if ((currentDClass = DClass.value(s)) >= 0) {
			s = st.getString();
		} else {
			currentDClass = DClass.IN;
		}
	}

	if ((currentType = Type.value(s)) < 0)
		throw st.exception("Invalid type '" + s + "'");
}

private long
parseUInt32(String s) {
	if (!Character.isDigit(s.charAt(0)))
		return -1;
	try {
		long l = Long.parseLong(s);
		if (l < 0 || l > 0xFFFFFFFFL)
			return -1;
		return l;
	}
	catch (NumberFormatException e) {
		return -1;
	}
}

private void
startGenerate() throws IOException {
	String s;
	int n;

	// The first field is of the form start-end[/step]
	// Regexes would be useful here.
	s = st.getIdentifier();
	n = s.indexOf("-");
	if (n < 0)
		throw st.exception("Invalid $GENERATE range specifier: " + s);
	String startstr = s.substring(0, n);
	String endstr = s.substring(n + 1);
	String stepstr = null;
	n = endstr.indexOf("/");
	if (n >= 0) {
		stepstr = endstr.substring(n + 1);
		endstr = endstr.substring(0, n);
	}
	genStart = parseUInt32(startstr);
	genCurrent = genStart;
	genEnd = parseUInt32(endstr);
	if (stepstr != null)
		genStep = parseUInt32(stepstr);
	else
		genStep = 1;
	if (genStart < 0 || genEnd < 0 || genStart > genEnd || genStep <= 0)
		throw st.exception("Invalid $GENERATE range specifier: " + s);

	// The next field is the name specification.
	genNameSpec = st.getIdentifier();

	// Then the ttl/class/type, in the same form as a normal record.
	// Only some types are supported.
	parseTTLClassAndType();
	if (currentType != Type.PTR &&
	    currentType != Type.CNAME &&
	    currentType != Type.DNAME &&
	    currentType != Type.A &&
	    currentType != Type.AAAA &&
	    currentType != Type.NS)
		throw st.exception("$GENERATE does not support " +
				   Type.string(currentType) + " records");

	// Next comes the rdata specification.
	genRdataSpec = st.getIdentifier();

	// That should be the end.  However, we don't want to move past the
	// line yet, so put back the EOL after reading it.
	st.getEOL();
	st.unget();

	generating = true;
}

private void
endGenerate() throws IOException {
	// Read the EOL that we put back before.
	st.getEOL();

	generating = false;
}

private String
substitute(String spec, long n) throws IOException {
	boolean escaped = false;
	byte [] str = spec.getBytes();
	StringBuffer sb = new StringBuffer();

	for (int i = 0; i < str.length; i++) {
		char c = (char)(str[i] & 0xFF);
		if (escaped) {
			sb.append(c);
			escaped = false;
		} else if (c == '\\') {
			if (i + 1 == str.length)
				throw st.exception("Invalid escape character");
			escaped = true;
		} else if (c == '$') {
			boolean negative = false;
			long offset = 0;
			long width = 0;
			long base = 10;
			if (i + 1 < str.length && str[i + 1] == '$') {
				// '$$' == literal '$' for backwards
				// compatibility with old versions of BIND.
				c = (char)(str[++i] & 0xFF);
				sb.append(c);
				continue;
			} else if (i + 1 < str.length && str[i + 1] == '{') {
				// It's a substitution with modifiers.
				i++;
				if (i + 1 < str.length && str[i + 1] == '-') {
					negative = true;
					i++;
				}
				while (i + 1 < str.length) {
					c = (char)(str[++i] & 0xFF);
					if (c == ',' || c == '}')
						break;
					if (c < '0' || c > '9')
						throw st.exception(
							"invalid offset");
					c -= '0';
					offset *= 10;
					offset += c;
				}
				if (negative)
					offset = -offset;

				if (c == ',') {
					while (i + 1 < str.length) {
						c = (char)(str[++i] & 0xFF);
						if (c == ',' || c == '}')
							break;
						if (c < '0' || c > '9')
							throw st.exception(
							   "invalid width");
						c -= '0';
						width *= 10;
						width += c;
					}
				}

				if (c == ',') {
					if  (i + 1 == str.length)
						throw st.exception(
							   "invalid base");
					c = (char)(str[++i] & 0xFF);
					if (c == 'o')
						base = 8;
					else if (c == 'x')
						base = 16;
					else if (c != 'd')
						throw st.exception(
							   "invalid base");
				}

				if (i + 1 == str.length || str[i + 1] != '}')
					throw st.exception("invalid modifiers");
				i++;
			}
			long v = n + offset;
			if (v < 0)
				throw st.exception("invalid offset expansion");
			String number;
			if (base == 8)
				number = Long.toOctalString(v);
			else if (base == 16)
				number = Long.toHexString(v);
			else
				number = Long.toString(v);
			if (width != 0 && width > number.length()) {
				int zeros = (int)width - number.length();
				while (zeros-- > 0)
					sb.append('0');
			}
			sb.append(number);
		} else {
			sb.append(c);
		}
	}
	return sb.toString();
}

private Record
nextGenerated() throws IOException {
	if (genCurrent > genEnd)
		return null;
	String namestr = substitute(genNameSpec, genCurrent);
	Name name = Name.fromString(namestr, origin);
	String rdata = substitute(genRdataSpec, genCurrent);
	try {
		Record rec = Record.fromString(name, currentType, currentDClass,
					       currentTTL, rdata, origin);
		genCurrent += genStep;
		return rec;
	}
	catch (Tokenizer.TokenizerException e) {
		throw st.exception("Parsing $GENERATE: " + e.getBaseMessage());
	}
	catch (TextParseException e) {
		throw st.exception("Parsing $GENERATE: " + e.getMessage());
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
	if (generating) {
		Record rec = nextGenerated();
		if (rec != null)
			return rec;
		endGenerate();
	}
	while (true) {
		Name name;

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
			} else  if (s.equalsIgnoreCase("$GENERATE")) {
				if (generating)
					throw new IllegalStateException
						("cannot nest $GENERATE");
				startGenerate();
				return nextGenerated();
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

		parseTTLClassAndType();
		last = Record.fromString(name, currentType, currentDClass,
					 currentTTL, st, origin);
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
