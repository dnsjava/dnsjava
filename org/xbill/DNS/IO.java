// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;

public class IO {

static String
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
