// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import DNS.utils.*;

public final class Section {

private static StringValueTable sections = new StringValueTable();
private static StringValueTable longSections = new StringValueTable();

public static final byte QUESTION	= 0;
public static final byte ANSWER		= 1;
public static final byte AUTHORITY	= 2;
public static final byte ADDITIONAL	= 3;

/* Aliases for dynamic update */
public static final byte ZONE		= 0;
public static final byte PREREQ		= 1;
public static final byte UPDATE		= 2;

static {
	sections.put2(QUESTION, "qd");
	sections.put2(ANSWER, "an");
	sections.put2(AUTHORITY, "au");
	sections.put2(ADDITIONAL, "ad");

	longSections.put2(QUESTION, "QUESTIONS");
	longSections.put2(ANSWER, "ANSWERS");
	longSections.put2(AUTHORITY, "AUTHORITY RECORDS");
	longSections.put2(ADDITIONAL, "ADDITIONAL RECORDS");

}

public static String
string(int i) {
	String s = sections.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

public static String
longString(int i) {
	String s = longSections.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

public static byte
value(String s) {
	byte i = (byte) sections.getValue(s.toUpperCase());
	if (i >= 0)
		return i;
	try {
		return Byte.parseByte(s);
	}
	catch (Exception e) {
		return (-1);
	}
}

}
