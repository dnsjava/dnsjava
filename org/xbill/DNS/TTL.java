// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

public final class TTL {

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

public static void main(String [] args) {
	String [] strings = {"1S", "1M", "1m", "1M1S", "1D", "1H1D", "1d1h", "1w", "12345"};
	for (int i = 0; i < strings.length; i++)
		System.out.println(strings[i] + " = " + parseTTL(strings[i]));
}

}
