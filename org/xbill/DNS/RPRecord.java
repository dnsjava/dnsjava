// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Responsible Person Record - lists the mail address of a responsible person
 * and a domain where TXT records are available.
 *
 * @author Tom Scola <tscola@research.att.com>
 * @author Brian Wellington
 */

public class RPRecord extends Record {

private Name mailbox;
private Name textDomain;

RPRecord() {}

Record
getObject() {
	return new RPRecord();
}

/**
 * Creates an RP Record from the given data
 * @param mailbox The responsible person
 * @param textDomain The address where TXT records can be found
 */
public
RPRecord(Name name, int dclass, long ttl, Name mailbox, Name textDomain) {
	super(name, Type.RP, dclass, ttl);

	if (!mailbox.isAbsolute())
		throw new RelativeNameException(mailbox);
	this.mailbox = mailbox;
	if (!textDomain.isAbsolute())
		throw new RelativeNameException(textDomain);
	this.textDomain = textDomain;
}

void
rrFromWire(DNSInput in) throws IOException {
	mailbox = new Name(in);
	textDomain = new Name(in);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	mailbox = st.getName(origin);
	textDomain = st.getName(origin);
}

/** Converts the RP Record to a String */
String
rrToString() {
	StringBuffer sb = new StringBuffer();
	sb.append(mailbox);
	sb.append(" ");
	sb.append(textDomain);
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
