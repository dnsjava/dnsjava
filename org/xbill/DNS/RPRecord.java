// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Responsible Person Record - lists the mail address of a responsible person
 * and a domain where TXT records are available.
 *
 * @author Tom Scola <tscola@research.att.com>
 * @author Brian Wellington
 */

public class RPRecord extends Record {

private static RPRecord member = new RPRecord();

private Name mailbox;
private Name textDomain;

private
RPRecord() {}

private
RPRecord(Name name, short dclass, int ttl) {
	super(name, Type.RP, dclass, ttl);
}

static RPRecord
getMember() {
	return member;
}

/**
 * Creates an RP Record from the given data
 * @param mailbox The responsible person
 * @param textdomain The address where TXT records can be found
 */
public
RPRecord(Name name, short dclass, int ttl, Name mailbox, Name textDomain) {
	this(name, dclass, ttl);
	this.mailbox = mailbox;
	this.textDomain = textDomain;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	RPRecord rec = new RPRecord(name, dclass, ttl);
	if (in == null)
		return rec;
	rec.mailbox = new Name(in);
	rec.textDomain = new Name(in);
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	RPRecord rec = new RPRecord(name, dclass, ttl);
	rec.mailbox = Name.fromString(st.nextToken(), origin);
	rec.mailbox.checkAbsolute("read an RP record");
	rec.textDomain = Name.fromString(st.nextToken(), origin);
	rec.textDomain.checkAbsolute("read an RP record");
	return rec;
}

/** Converts the RP Record to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (mailbox != null && textDomain != null) {
		sb.append(mailbox);
		sb.append(" ");
		sb.append(textDomain);
	}
	return sb.toString();
}

/** Gets the mailbox address of the RP Record */
public Name
getMailbox() {
	return mailbox;
}

/** Gets the text domain info of the RP Record */
public Name
getTextDomain() {
	return textDomain;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (mailbox == null || textDomain == null)
		return;

	mailbox.toWire(out, null, canonical);
	textDomain.toWire(out, null, canonical);
}

}
