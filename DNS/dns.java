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

public static void
init(String defaultResolver) {
	Resolver.setDefaultResolver(defaultResolver);
}

public static Record []
getRecords(Resolver res, String name, short type, short dclass) {
	Message query = new Message();
	Message response;
	Record question;
	Record [] answers;
	int answerCount = 0, i = 0;
	Enumeration e;

	if (res == _res && _res == null) {
		try {
			_res = new Resolver();
		}
		catch (UnknownHostException uhe) {
			System.out.println("Failed to initialize resolver");
			System.exit(-1);
		}
	}

	query.getHeader().setOpcode(Opcode.QUERY);
	query.getHeader().setFlag(Flags.RD);
	question = Record.newRecord(new Name(name), type, dclass);
	query.addRecord(Section.QUESTION, question);

	try {
		response = res.send(query);
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
getRecords(Resolver res, String name, short type) {
	return getRecords(res, name, type, DClass.IN);
}

public static Record []
getRecords(String name, short type, short dclass) {
	return getRecords(_res, name, type, dclass);
}

public static Record []
getRecords(String name, short type) {
	return getRecords(_res, name, type, DClass.IN);
}


public static Record []
getRecordsByAddress(Resolver res, String addr, short type) {
	byte [] address;
	try {
		address = InetAddress.getByName(addr).getAddress();
	}
	catch (UnknownHostException e) {
		return null;
	}
	StringBuffer sb = new StringBuffer();
	for (int i = 3; i >= 0; i--) {
		sb.append(address[i] & 0xFF);
		sb.append(".");
	}
	sb.append(".IN-ADDR.ARPA.");
	String name = sb.toString();
	return getRecords(res, name, type, DClass.IN);
}

public static Record []
getRecordsByAddress(String addr, short type) {
	return getRecordsByAddress(_res, addr, type);
}

}
