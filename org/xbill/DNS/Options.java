// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;

/**
 * General options.
 * bindttl - Print TTLs in BIND format
 * noprintin - Don't print the class of a record if it's IN
 * nohex - Don't print anything in hex (KEY flags, for example)
 * pqdn - Allow partially qualified domain names
 * 2065sig - Omit the labels field from the SIG record's text format, as
 *	specified in RFC 2065 and changed in RFC 2535
 *
 * @author Brian Wellington
 */

public final class Options {

private static Hashtable table;

static {
	table = new Hashtable();
	String s = System.getProperty("dnsjava.options");
	if (s != null) {
		StringTokenizer st = new StringTokenizer(s, ",");
		while (st.hasMoreTokens())
			set(st.nextToken());
	}
}

private
Options() {}

public static void
set(String option) {
	table.put(option.toLowerCase(), "true");
}

public static void
set(String option, String value) {
	table.put(option.toLowerCase(), value.toLowerCase());
}

public static void
unset(String option) {
	table.remove(option.toLowerCase());
}

public static boolean
check(String option) {
	return (table.get(option.toLowerCase()) != null);
}

}
