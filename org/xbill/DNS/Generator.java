// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;

/**
 * A representation of a $GENERATE statement in a master file.
 *
 * @author Brian Wellington
 */

public class Generator {

/** The start of the range. */
public long start;

/** The end of the range. */
public long end;

/** The end of the range. */
public long step;

/** The pattern to use for generating record names. */
public final String namePattern;

/** The type of the generated records. */
public final int type;

/** The class of the generated records. */
public final int dclass;

/** The ttl of the generated records. */
public final long ttl;

/** The pattern to use for generating record data. */
public final String rdataPattern;

/** The origin to append when relative names are seen. */
public final Name origin;

private long current;

Generator(long start, long end, long step, String namePattern,
	  int type, int dclass, long ttl, String rdataPattern, Name origin)
{
	this.start = start;
	this.end = end;
	this.step = step;
	this.namePattern = namePattern;
	this.type = type;
	this.dclass = dclass;
	this.ttl = ttl;
	this.rdataPattern = rdataPattern;
	this.origin = origin;
	this.current = 0;
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
				throw new TextParseException
						("invalid escape character");
			escaped = true;
		} else if (c == '$') {
			boolean negative = false;
			long offset = 0;
			long width = 0;
			long base = 10;
			boolean wantUpperCase = false;
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
						throw new TextParseException(
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
							throw new
							   TextParseException(
							   "invalid width");
						c -= '0';
						width *= 10;
						width += c;
					}
				}

				if (c == ',') {
					if  (i + 1 == str.length)
						throw new TextParseException(
							   "invalid base");
					c = (char)(str[++i] & 0xFF);
					if (c == 'o')
						base = 8;
					else if (c == 'x')
						base = 16;
					else if (c == 'X') {
						base = 16;
						wantUpperCase = true;
					}
					else if (c != 'd')
						throw new TextParseException(
							   "invalid base");
				}

				if (i + 1 == str.length || str[i + 1] != '}')
					throw new TextParseException
						("invalid modifiers");
				i++;
			}
			long v = n + offset;
			if (v < 0)
				throw new TextParseException
						("invalid offset expansion");
			String number;
			if (base == 8)
				number = Long.toOctalString(v);
			else if (base == 16)
				number = Long.toHexString(v);
			else
				number = Long.toString(v);
			if (wantUpperCase)
				number = number.toUpperCase();
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

/**
 * Constructs and returns the next record in the expansion.
 */
public Record
nextRecord() throws IOException {
	if (current > end)
		return null;
	String namestr = substitute(namePattern, current);
	Name name = Name.fromString(namestr, origin);
	String rdata = substitute(rdataPattern, current);
	current += step;
	return Record.fromString(name, type, dclass, ttl, rdata, origin);
}

/**
 * Constructs and returns all records in the expansion.
 */
public Record []
expand() throws IOException {
	List list = new ArrayList();
	for (long i = start; i < end; i += step) {
		String namestr = substitute(namePattern, current);
		Name name = Name.fromString(namestr, origin);
		String rdata = substitute(rdataPattern, current);
		list.add(Record.fromString(name, type, dclass, ttl,
					   rdata, origin));
	}
	return (Record []) list.toArray(new Record[list.size()]);
}

}
