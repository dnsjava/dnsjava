// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

/* High level API */

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;

public final class dns {

private static Resolver _res;

static boolean
matchType(short type1, short type2) {
	return (type1 == Type.ANY || type2 == Type.ANY || type1 == type2);
}

public static String
inaddrString(InetAddress addr) {
	byte [] address = addr.getAddress();
	StringBuffer sb = new StringBuffer();
	for (int i = 3; i >= 0; i--) {
		sb.append(address[i] & 0xFF);
		sb.append(".");
	}
	sb.append(".IN-ADDR.ARPA.");
	return sb.toString();
}

public static String
inaddrString(String s) {
	InetAddress address;
	try {
		address = InetAddress.getByName(s);
	}
	catch (UnknownHostException e) {
		return null;
	}
	return inaddrString(address);
}

public static void
init(String defaultResolver) {
	Resolver.setDefaultResolver(defaultResolver);
}

public static void
setResolver(Resolver res) {
	_res = res;
}

public static Record []
getRecords(String name, short type, short dclass) {
	Message query;
	Message response;
	Record question;
	Record [] answers;
	int answerCount = 0, i = 0;
	Enumeration e;

	if (!Type.isRR(type) && type != Type.ANY)
		return null;

	if (_res == null) {
		try {
			_res = new Resolver();
		}
		catch (UnknownHostException uhe) {
			System.out.println("Failed to initialize resolver");
			System.exit(-1);
		}
	}

	query = new Message();
	query.getHeader().setOpcode(Opcode.QUERY);
	query.getHeader().setFlag(Flags.RD);
	question = Record.newRecord(new Name(name), type, dclass);
	query.addRecord(Section.QUESTION, question);

	try {
		response = _res.send(query);
	}
	catch (IOException ioe) {
		return null;
	}

	if (response.getHeader().getRcode() != Rcode.NOERROR)
		return null;

	e = response.getSection(Section.ANSWER);
	while (e.hasMoreElements()) {
		Record r = (Record)e.nextElement();
		if (matchType(r.getType(), type))
			answerCount++;
	}

	if (answerCount == 0)
		return null;

	answers = new Record[answerCount];

	e = response.getSection(Section.ANSWER);
	while (e.hasMoreElements()) {
		Record r = (Record)e.nextElement();
		if (matchType(r.getType(), type))
			answers[i++] = r;
	}

	return answers;
}

public static Record []
getRecords(String name, short type) {
	return getRecords(name, type, DClass.IN);
}


public static Record []
getRecordsByAddress(String addr, short type) {
	String name = inaddrString(addr);
	return getRecords(name, type, DClass.IN);
}

}
