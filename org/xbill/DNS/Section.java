// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Constants and functions relating to DNS message sections
 *
 * @author Brian Wellington
 */

public final class Section {

private static StringValueTable sections = new StringValueTable();
private static StringValueTable longSections = new StringValueTable();
private static StringValueTable updSections = new StringValueTable();

/** The question (first) section */
public static final byte QUESTION	= 0;

/** The answer (second) section */
public static final byte ANSWER		= 1;

/** The authority (third) section */
public static final byte AUTHORITY	= 2;

/** The additional (fourth) section */
public static final byte ADDITIONAL	= 3;

/* Aliases for dynamic update */
/** The zone (first) section of a dynamic update message */
public static final byte ZONE		= 0;

/** The prerequisite (second) section of a dynamic update message */
public static final byte PREREQ		= 1;

/** The update (third) section of a dynamic update message */
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

	updSections.put2(ZONE, "ZONE");
	updSections.put2(PREREQ, "PREREQUISITES");
	updSections.put2(UPDATE, "UPDATE RECORDS");
	updSections.put2(ADDITIONAL, "ADDITIONAL RECORDS");

}

private
Section() {}


/** Converts a numeric Section into an abbreviation String */
public static String
string(int i) {
	String s = sections.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

/** Converts a numeric Section into a full description String */
public static String
longString(int i) {
	String s = longSections.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

/**
 * Converts a numeric Section into a full description String for an update
 * Message.
 */
public static String
updString(int i) {
	String s = updSections.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

/** Converts a String representation of a Section into its numeric value */
public static byte
value(String s) {
	byte i = (byte) sections.getValue(s.toLowerCase());
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
