// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

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

static void
check(long i) {
	if (i < 0 || i > 0xFFFFFFFFL)
		throw new InvalidTTLException(i);
}

/**
 * Parses a BIND-stype TTL
 * @return The TTL as a number of seconds
 * @throws NumberFormatException The TTL was not a valid TTL.
 */
public static long
parseTTL(String s) {
	if (s == null || s.length() == 0 || !Character.isDigit(s.charAt(0)))
		throw new NumberFormatException();
	long value = 0;
	long ttl = 0;
	for (int i = 0; i < s.length(); i++) {
		char c = s.charAt(i);
		long oldvalue = value;
		if (Character.isDigit(c)) {
			value = (value * 10) + Character.getNumericValue(c);
			if (value < oldvalue)
				throw new NumberFormatException();
		} else {
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
			if (ttl > 0xFFFFFFFFL)
				throw new NumberFormatException();
		}
	}
	if (ttl == 0) {
		ttl = value;
		if (ttl > 0xFFFFFFFFL)
			throw new NumberFormatException();
	}
	return ttl;
}

public static String
format(long ttl) {
	TTL.check(ttl);
	StringBuffer sb = new StringBuffer();
	long secs, mins, hours, days, weeks;
	secs = ttl % 60;
	ttl /= 60;
	mins = ttl % 60;
	ttl /= 60;
	hours = ttl % 24;
	ttl /= 24;
	days = ttl % 7;
	ttl /= 7;
	weeks = ttl;
	if (weeks > 0)
		sb.append(weeks + "W");
	if (days > 0)
		sb.append(days + "D");
	if (hours > 0)
		sb.append(hours + "H");
	if (mins > 0)
		sb.append(mins + "M");
	if (secs > 0 || (weeks == 0 && days == 0 && hours == 0 && mins == 0))
		sb.append(secs + "S");
	return sb.toString();
}

}
