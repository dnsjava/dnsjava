// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;

/**
 * Routines to perform various input/output operations
 */

public class IO {

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
		s = stripTrailing(br.readLine());
		if (s == null)
			return sb.toString();
		if (s.endsWith(")")) {
			sb.append(s.substring(0, s.length() - 1));
			break;
		}
		else
			sb.append(s);
	}
	return sb.toString();
}

/**
 * Formats a base64-encoded String into presentable output
 * @param s The base64-encoded String
 * @param lineLength The number of characters per line
 * @param prefix A string prefixing the characters on each line
 * @param addClose Whether to add a close parenthesis or not
 * @return A String representing the formatted output
 */
public static String
formatBase64String(String s, int lineLength, String prefix, boolean addClose) {
	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < s.length(); i += lineLength) {
		sb.append (prefix);
		if (i + lineLength >= s.length()) {
			sb.append(s.substring(i));
			if (addClose)
				sb.append(" )");
		}
		else {
			sb.append(s.substring(i, i+64));
			sb.append("\n");
		}
	}
	return sb.toString();
}

}
