// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.utils;

import java.io.*;
import java.util.*;

/**
 * A class similar to StringTokenizer, with a few differences making it more
 * suitable.  The \ character is used as an escape character, allowing
 * delimiters to be escaped.  Quoted strings (delimited by double quotes)
 * are treated as one token.
 *
 * @author Brian Wellington
 */

public class MyStringTokenizer implements Enumeration {

private char [] string;
private String delim;
private boolean returnTokens;
private int current;
private String putBack;

/** Creates a new instance of MyStringTokenizer.
 * @param s The string to be tokenized
 * @param delim A string containing all delimiters
 * @param returnTokens If true, return delimiters as tokens.  This
 * differs from StringTokenizer in that adjacent delimiters are returned
 * in the same token.
 */
public
MyStringTokenizer(String s, String delim, boolean returnTokens) {
	string = new char[s.length()];
	s.getChars(0, s.length(), string, 0);
	this.delim = delim;
	this.returnTokens = returnTokens;
	current = 0;
}

/** Creates a new instance of MyStringTokenizer.
 * @param s The string to be tokenized
 * @param delim A string containing all delimiters
 */
public
MyStringTokenizer(String s, String delim) {
	this(s, delim, false);
}

/** Creates a new instance of MyStringTokenizer, with whitespace delimiters
 * (space, tab, newline).
 * @param s The string to be tokenized
 */
public
MyStringTokenizer(String s) {
	this(s, " \t\n\r", false);
}

private boolean
isDelim(int i) {
	return (delim.indexOf(string[i]) >= 0);
}

/** Returns true if there are more tokens in the string. */
public boolean
hasMoreTokens() {
	if (putBack != null)
		return true;
	if (current >= string.length)
		return false;
	if (!isDelim(current) || returnTokens)
		return true;
	int t = current;
	while (t < string.length && isDelim(t))
		t++;
	return (t < string.length);
}

/** Returns true if there are more tokens in the string. */
public boolean
hasMoreElements() {
	return hasMoreTokens();
}

/**
 * Returns true if there are more delimiters in the string.  This should
 * only be called if hasMoreTokens is false, to determine if the string
 * contains trailing delimiters.
 */
public boolean
hasMoreDelimiters() {
	return (current < string.length);
}

/** Returns the next token */
public String
nextToken() {
	if (putBack != null) {
		String s = putBack;
		putBack = null;
		return s;
	}
	int start = current;
	if (current >= string.length)
		return null;
	if (isDelim(current)) {
		/* This is whitespace */
		while (current < string.length && isDelim(current))
			current++;
		if (returnTokens)
			return new String(string, start, current - start);
		else if (current >= string.length)
			return null;
	}
	boolean quoted = false;
	boolean escaped = false;
	StringBuffer sb = new StringBuffer();
	while (true) {
		if (current == string.length)
			break;
		if (escaped) {
			sb.append('\\');
			sb.append(string[current]);
			escaped = false;
		} else if (string[current] == '\\')
			escaped = true;
		else if (string[current] == '"') {
			if (quoted) {
				current++;
				break;
			} else
				quoted = true;
		} else if (quoted)
			sb.append(string[current]);
		else if (string[current] == '"') 
			quoted = true;
		else if (isDelim(current))
			break;
		else
			sb.append(string[current]);
		current++;
	}
	return sb.toString();
}

/** Returns the next token */
public Object
nextElement() {
	return nextToken();
}

/**
 * Specifies a string to be added to the MyStringTokenizer object.  The next
 * call to nextToken() will return this string.
 */
public void
putBackToken(String s) {
	putBack = s;
}

/** Returns a concatenation of all remaining tokens */
public String
remainingTokens() {
	StringBuffer sb = new StringBuffer();
	while (hasMoreTokens())
		sb.append(nextToken());
	return sb.toString();
}

}
