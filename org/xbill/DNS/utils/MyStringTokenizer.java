// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.utils;

import java.io.*;
import java.util.*;

/* This should be compatible with StringTokenizer, with the following
 * exceptions:
 *   - \ is an escape character.  This allows escaping delimiters and \xxx
 *     decimal values.
 *   - quoted strings are treated as one token ("one token")
 *   - no support for changing delimiters on the fly
 *
 * These should probably be optional.
 *
 * This could do multiline handling, but I think I should leave that in
 *    IO.readExtendedLine.
 */

public class MyStringTokenizer implements Enumeration {

char [] string;
String delim;
boolean returnTokens;
int current;
String putBack;

public
MyStringTokenizer(String _s, String _delim, boolean _returnTokens) {
	string = new char[_s.length()];
	_s.getChars(0, _s.length(), string, 0);
	delim = _delim;
	returnTokens = _returnTokens;
	current = 0;
}

public
MyStringTokenizer(String _s, String _delim) {
	this(_s, _delim, false);
}

public
MyStringTokenizer(String _s) {
	this(_s, " \t\n\r", false);
}

private boolean
isDelim(int i) {
	return (delim.indexOf(string[i]) >= 0);
}

public boolean
hasMoreTokens() {
	if (current >= string.length)
		return false;
	if (!isDelim(current) || returnTokens)
		return true;
	int t = current;
	while (t < string.length && isDelim(t))
		t++;
	return (t < string.length);
}

public boolean
hasMoreElements() {
	return hasMoreTokens();
}

/* This should _only_ be called if hasMoreTokens == false */
public boolean
hasMoreDelimiters() {
	return (current < string.length);
}

public String
nextToken() {
	if (putBack != null) {
		String s = putBack;
		putBack = null;
		return s;
	}
	int start = current;
	if (isDelim(current)) {
		/* This is whitespace */
		while (current < string.length && isDelim(current))
			current++;
		if (returnTokens)
			return new String(string, start, current - start);
	}
	boolean quoted = false;
	boolean escaped = false;
	StringBuffer sb = new StringBuffer();
	while (true) {
		if (current == string.length)
			break;
		if (escaped) {
			if (Character.digit(string[current], 10) >= 0) {
				String s = new String(string, current, 3);
				int i = Integer.parseInt(s);
				sb.append((char)i);
				current += 2;
			}
			else
				sb.append(string[current]);
			escaped = false;
		}
		else if (quoted) {
			if (string[current] == '"') {
				current++;
				break;
			}
			else
				sb.append(string[current]);
		}
		else {
			if (string[current] == '"') 
				quoted = true;
			else if (string[current] == '\\')
				escaped = true;
			else if (isDelim(current)) {
				break;
			}
			else
				sb.append(string[current]);
		}
		current++;
	}
	return sb.toString();
}

public Object
nextElement() {
	return nextToken();
}

public void
putBackToken(String s) {
	putBack = s;
}

public static void
main(String args[]) throws IOException {

        InputStreamReader isr = new InputStreamReader(System.in);
        BufferedReader br = new BufferedReader(isr);

	while (true) {
		MyStringTokenizer st = new MyStringTokenizer(br.readLine());
		while (st.hasMoreTokens())
			System.out.println(st.nextToken());
	}
}

}
