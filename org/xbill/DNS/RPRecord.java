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

private Name mailbox;
private Name textDomain;

private
RPRecord() {}

/**
 * Creates an RP Record from the given data
 * @param mailbox The responsible person
 * @param textdomain The address where TXT records can be found
 */
public
RPRecord(Name _name, short _dclass, int _ttl, Name _mailbox, Name _textDomain) {
	super(_name, Type.RP, _dclass, _ttl);
	mailbox = _mailbox;
	textDomain = _textDomain;
}

RPRecord(Name _name, short _dclass, int _ttl, int length,
	 DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.RP, _dclass, _ttl);
	if (in == null)
		return;
	mailbox = new Name(in, c);
	textDomain = new Name(in, c);
}

RPRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	 Name origin)
throws IOException
{
        super(_name, Type.RP, _dclass, _ttl);
        mailbox = new Name(st.nextToken(), origin);
        textDomain = new Name(st.nextToken(), origin);
}

/** Converts the RP Record to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (mailbox == null || textDomain == null)
		return;

	mailbox.toWire(out, null);
	textDomain.toWire(out, null);
}

void
rrToWireCanonical(DataByteOutputStream out) throws IOException {
	if (mailbox == null || textDomain == null)
		return;

	mailbox.toWireCanonical(out);
	textDomain.toWireCanonical(out);
}

}
