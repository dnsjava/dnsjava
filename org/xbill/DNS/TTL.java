// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

/**
 * Routines for parsing BIND-style TTL values.  These values consist of
 * numbers followed by 1 letter units of time (W - week, D - day, H - hour,
 * M - minute, S - second).
 *
 * @author Brian Wellington
 */

public final class TTL {

private
TTL() {}

/**
 * Parses a BIND-stype TTL
 * @return The TTL as a number of seconds
 */
public static int
parseTTL(String s) throws NumberFormatException {
	if (s == null || !Character.isDigit(s.charAt(0)))
		throw new NumberFormatException();
	int value = 0, ttl = 0;
	for (int i = 0; i < s.length(); i++) {
		char c = s.charAt(i);
		if (Character.isDigit(c))
			value = (value * 10) + Character.getNumericValue(c);
		else {
			switch (Character.toUpperCase(c)) {
				case 'W': value *= 7;
				case 'D': value *= 24;
				case 'H': value *= 60;
				case 'M': value *= 60;
				case 'S': break;
				default:  throw new NumberFormatException();
			}
			ttl += value;
			value = 0;
		}
	}
	if (ttl == 0)
		ttl = value;
	return ttl;
}

public static String
format(int ttl) {
	StringBuffer sb = new StringBuffer();
	int secs, mins, hours, days, weeks;
	secs = ttl % 60;
	ttl /= 60;
	mins = ttl % 60;
	ttl /= 60;
	hours = ttl % 24;
	ttl /= 24;
	days = ttl % 7;
	ttl /= 7;
	weeks = ttl;
	if (weeks > 0) {
		sb.append(weeks);
		sb.append("W");
	}
	if (days > 0) {
		sb.append(days);
		sb.append("D");
	}
	if (hours > 0) {
		sb.append(hours);
		sb.append("H");
	}
	if (mins > 0) {
		sb.append(mins);
		sb.append("M");
	}
	if (secs > 0 || (weeks == 0 && days == 0 && hours == 0 && mins == 0)) {
		sb.append(secs);
		sb.append("S");
	}
	return sb.toString();
}

public static void main(String [] args) {
	String [] strings = {"1S", "1M", "1m", "1M1S", "1D", "1H1D", "1d1h",
			     "1w", "12345"};
	for (int i = 0; i < strings.length; i++) {
		int ttl = parseTTL(strings[i]);
		String s = TTL.format(ttl);
		System.out.println(strings[i] + " = " + ttl + " = " + s);
	}
}

}
