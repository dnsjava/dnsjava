// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

/* This should be compatible with StringTokenizer, with the following
 * exceptions:
 *   - \ is an escape character.  This allows escaping delimiters.
 *   - quoted strings are treated as one token ("one token")
 *   - no support for changing delimiters on the fly
 *
 * These should probably be optional.
 *
 * This could do multiline handling, but I think I should leave that in
 *    dnsIO.readExtendedLine.  This could also do octal number handling.
 */

public class MyStringTokenizer implements Enumeration {

char [] string;
String delim;
boolean returnTokens;
int current;

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

public boolean
hasMoreTokens() {
	return (current < string.length);
}

public boolean
hasMoreElements() {
	return hasMoreTokens();
}

public String
nextToken() {
	int start = current;
	if (delim.indexOf(string[current]) >= 0) {
		/* This is whitespace */
		while (current < string.length &&
		       delim.indexOf(string[current]) >= 0)
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
			sb.append(string[current]);
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
			else if (delim.indexOf(string[current]) >= 0) {
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
