// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

/* High level API */

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;

public final class dns {

private static Resolver res;
private static Cache cache;

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
setResolver(Resolver _res) {
	res = _res;
}

public static Record []
getRecords(String namestr, short type, short dclass, byte cred) {
	Message query;
	Message response;
	Record question;
	Record [] answers;
	int answerCount = 0, i = 0;
	Enumeration e;
	Name name = new Name(namestr);

/*System.out.println("lookup of " + name + " " + Type.string(type));*/
	if (!Type.isRR(type) && type != Type.ANY)
		return null;

	if (res == null) {
		try {
			res = new Resolver();
		}
		catch (UnknownHostException uhe) {
			System.out.println("Failed to initialize resolver");
			System.exit(-1);
		}
	}
	if (cache == null)
		cache = new Cache();

	CacheResponse cached = cache.lookupRecords(name, type, cred);
/*System.out.println(cached);*/
	if (cached.isSuccessful()) {
		RRset rrset = cached.answer();
		answerCount = rrset.size();
		e = rrset.rrs();
	}
	else if (cached.isNegative()) {
		answerCount = 0;
		e = null;
	}
	else {
		query = new Message();
		query.getHeader().setOpcode(Opcode.QUERY);
		query.getHeader().setFlag(Flags.RD);
		question = Record.newRecord(name, type, dclass);
		query.addRecord(Section.QUESTION, question);

		try {
			response = res.send(query);
		}
		catch (IOException ioe) {
			return null;
		}

		short rcode = response.getHeader().getRcode();
		if (rcode == Rcode.NOERROR || rcode == Rcode.NXDOMAIN)
			cache.addMessage(response);

		if (rcode != Rcode.NOERROR)
			return null;

		e = response.getSection(Section.ANSWER);
		while (e.hasMoreElements()) {
			Record r = (Record)e.nextElement();
			if (matchType(r.getType(), type))
				answerCount++;

		}

		e = response.getSection(Section.ANSWER);
	}

	if (answerCount == 0)
		return null;

	answers = new Record[answerCount];

	while (e.hasMoreElements()) {
		Record r = (Record)e.nextElement();
		if (matchType(r.getType(), type))
			answers[i++] = r;
	}

	return answers;
}

public static Record []
getRecords(String namestr, short type, short dclass) {
	return getRecords(namestr, type, dclass, Credibility.NONAUTH_ANSWER);
}

public static Record []
getAnyRecords(String namestr, short type, short dclass) {
	return getRecords(namestr, type, dclass, Credibility.AUTH_ADDITIONAL);
}

public static Record []
getRecords(String name, short type) {
	return getRecords(name, type, DClass.IN, Credibility.NONAUTH_ANSWER);
}

public static Record []
getAnyRecords(String name, short type) {
	return getRecords(name, type, DClass.IN, Credibility.AUTH_ADDITIONAL);
}

public static Record []
getRecordsByAddress(String addr, short type) {
	String name = inaddrString(addr);
	return getRecords(name, type, DClass.IN, Credibility.NONAUTH_ANSWER);
}

public static Record []
getAnyRecordsByAddress(String addr, short type) {
	String name = inaddrString(addr);
	return getRecords(name, type, DClass.IN, Credibility.AUTH_ADDITIONAL);
}

}
