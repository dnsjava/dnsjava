// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.net.*;
import java.io.*;
import java.util.*;

public class update {

static final int ZONE = dns.QUERY;
static final int PREREQUISITE = dns.ANSWER;
static final int UPDATE = dns.AUTHORITY;
static final int ADDITIONAL = dns.ADDITIONAL;

dnsMessage query;
dnsResolver res;
String server, origin;
int defaultTTL;
short defaultClass = dns.IN;

public
update(String _server) throws IOException {
	query = new dnsMessage();
	query.getHeader().setOpcode(dns.UPDATE);

	InputStreamReader isr = new InputStreamReader(System.in);
	BufferedReader br = new BufferedReader(isr);

	while (true) {
		System.out.print("> ");

		String line = dnsIO.readExtendedLine(br);
		MyStringTokenizer st = new MyStringTokenizer(line);
		if (!st.hasMoreTokens())
			continue;
		String operation = st.nextToken();

		if (operation.equals("server")) {
			server = st.nextToken();
			res = new dnsResolver(server);
		}

		else if (operation.equals("class")) {
			String s = st.nextToken();
			short newClass = dns.classValue(s);
			if (newClass > 0)
				defaultClass = newClass;
			else
				System.out.println("Invalid class " + newClass);
		}

		else if (operation.equals("ttl"))
			defaultTTL = Integer.parseInt(st.nextToken());

		else if (operation.equals("key")) {
			String keyname = st.nextToken();
			String keydata = st.nextToken();
			if (res == null)
				res = new dnsResolver(server);
			res.setTSIGKey(keyname, keydata);
		}

		else if (operation.equals("origin"))
			origin = st.nextToken();

		else if (operation.equals("send")) {
			if (res == null)
				res = new dnsResolver(server);
			sendUpdate();
		}

		else if (operation.equals("quit"))
			System.exit(0);

		else if (operation.equals("require"))
			System.out.println("require operation not supported");

		else if (operation.equals("prohibit"))
			System.out.println("prohibit operation not supported");

		else if (operation.equals("add"))
			doAdd(st);

		else if (operation.equals("delete"))
			System.out.println("delete operation not supported");

		else if (operation.equals("glue"))
			System.out.println("glue operation not supported");

		else
			System.out.println("invalid keyword: " + operation);
	}
}

void
sendUpdate() throws IOException {
	if (query.getHeader().getCount(ZONE) == 0) {
		Vector updates = query.getSection(UPDATE);
		if (updates == null) {
			System.out.println("Invalid update - no records");
			return;
		}
		dnsRecord r = (dnsRecord) query.getSection(UPDATE).elementAt(0);
		dnsName zone = new dnsName(r.getName(), 1);
		dnsRecord soa = dnsRecord.newRecord(zone, dns.SOA, r.dclass);
		query.addRecord(ZONE, soa);
	}

	dnsMessage response = res.send(query);
	if (response == null)
		return;

	System.out.print(";; ->>HEADER<<- ");
	System.out.print("opcode: ");
	System.out.print(dns.opcodeString(response.getHeader().getOpcode()));
	System.out.print(", status: ");
	System.out.print(dns.rcodeString(response.getHeader().getRcode()));
	System.out.println(", id: " + response.getHeader().getID());

	
	System.out.print(";; flags: " + response.getHeader().printFlags());
	System.out.print("; ");
	for (int i = 0; i < 4; i++) {
		System.out.print(dns.sectionString(i));
		System.out.print(": ");
		System.out.print(response.getHeader().getCount(i));
		System.out.print(" ");
	}
	System.out.println();

	System.out.println(";; done");
}

void
doAdd(MyStringTokenizer st) throws IOException {
	dnsRecord rec;

	String qualifier = st.nextToken();
	if (qualifier.equals("-r")) {
		dnsName name = new dnsName(st.nextToken(), origin);
		int ttl;
		short dclass, type;

		String s = st.nextToken();

		try {
			ttl = Integer.parseInt(s);
			s = st.nextToken();
		}
		catch (NumberFormatException e) {
			ttl = defaultTTL;
		}

		if ((dclass = dns.classValue(s)) >= 0)
			s = st.nextToken();
		else
			dclass = defaultClass;

		if ((type = dns.typeValue(s)) < 0)
			throw new IOException("Parse error");

		rec = dnsRecord.fromString(st, name, ttl, type, dclass);
		query.addRecord(UPDATE, rec);
		System.out.println(rec);
	}
	else {
		System.out.println("qualifier " + qualifier + " not supported");
		return;
	}
	

}

static void
usage() {
	System.out.println("Usage: update [@server]");
	System.exit(0);
}

public static void
main(String argv[]) throws IOException {
	String server = null;

	if (argv.length == 0)
		server = "localhost";
	else if (argv.length == 1 &&  argv[0].startsWith("@"))
		server = argv[0].substring(1);
	else
		usage();

	update u = new update(server);
}

}
