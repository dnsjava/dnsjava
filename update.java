// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.net.*;
import java.io.*;
import java.util.*;

public class update {

static final int ZONE = dns.QUERY;
static final int PREREQ = dns.ANSWER;
static final int UPDATE = dns.AUTHORITY;
static final int ADDITIONAL = dns.ADDITIONAL;

dnsMessage query;
dnsResolver res;
String server;
dnsName origin;
int defaultTTL;
short defaultClass = dns.IN;
short lastRcode;

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

		else if (operation.equals("key")) {
			String keyname = st.nextToken();
			String keydata = st.nextToken();
			if (res == null)
				res = new dnsResolver(server);
			res.setTSIGKey(keyname, keydata);
		}

		else if (operation.equals("port")) {
			if (res == null)
				res = new dnsResolver(server);
			res.setPort(Short.parseShort(st.nextToken()));
		}

		else if (operation.equals("tcp")) {
			if (res == null)
				res = new dnsResolver(server);
			res.setTCP(true);
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

		else if (operation.equals("origin"))
			origin = new dnsName(st.nextToken());

		else if (operation.equals("require"))
			doRequire(st);

		else if (operation.equals("prohibit"))
			doProhibit(st);

		else if (operation.equals("add"))
			doAdd(st);

		else if (operation.equals("delete"))
			doDelete(st);

		else if (operation.equals("glue"))
			doGlue(st);

		else if (operation.equals("help")) {
			if (st.hasMoreTokens())
				help(st.nextToken());
			else
				help(null);
		}

		else if (operation.equals("send")) {
			if (res == null)
				res = new dnsResolver(server);
			sendUpdate();
			query = new dnsMessage();
			query.getHeader().setOpcode(dns.UPDATE);
		}

		else if (operation.equals("quit"))
			System.exit(0);

		else if (operation.equals("assert")) {
			String s = st.nextToken();
			String rcodeString = dns.rcodeString(lastRcode);
			if (!s.equalsIgnoreCase(rcodeString)) {
				System.out.println("Expected rcode " + s +
						   ", received " + rcodeString);
				if (st.hasMoreTokens()) {
					s = st.nextToken();
					System.out.println(s);
				}
				System.exit(-1);
			}
		}

		else
			System.out.println("invalid keyword: " + operation);
	}
}

void
sendUpdate() throws IOException {
	if (query.getHeader().getCount(ZONE) == 0) {
		dnsName zone = origin;
		short dclass = defaultClass;
		if (zone == null) {
			Vector updates = query.getSection(UPDATE);
			if (updates == null) {
				System.out.println("Invalid update");
				return;
			}
			dnsRecord r = (dnsRecord) updates.elementAt(0);
			zone = new dnsName(r.getName(), 1);
			dclass = r.dclass;
		}
		dnsRecord soa = dnsRecord.newRecord(zone, dns.SOA, dclass);
		query.addRecord(ZONE, soa);
	}

	dnsMessage response = res.send(query);
	if (response == null)
		return;

	lastRcode = response.getHeader().getRcode();

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

/* 
 * <name> [ttl] [class] <type> <data>
 * Ignore the class, if present.
 */
dnsRecord
parseRR(MyStringTokenizer st, short classValue, int TTLValue)
throws IOException
{
	dnsName name = new dnsName(st.nextToken(), origin);
	int ttl;
	short type;

	String s = st.nextToken();

	try {
		ttl = Integer.parseInt(s);
		s = st.nextToken();
	}
	catch (NumberFormatException e) {
		ttl = TTLValue;
	}

	if (dns.classValue(s) >= 0)
		s = st.nextToken();

	if ((type = dns.typeValue(s)) < 0)
		throw new IOException("Parse error");

	return dnsRecord.fromString(name, type, classValue, ttl, st, origin);
}

/* 
 * <name> <type>
 */
dnsRecord
parseRRExistence(MyStringTokenizer st, short classValue) throws IOException {
	dnsName name = new dnsName(st.nextToken(), origin);
	short type;

	if ((type = dns.typeValue(st.nextToken())) < 0)
		throw new IOException("Parse error");

	return dnsRecord.newRecord(name, type, classValue, 0);
	
}

/* 
 * <name>
 */
dnsRecord
parseName(MyStringTokenizer st, short classValue) throws IOException {
	dnsName name = new dnsName(st.nextToken(), origin);

	return dnsRecord.newRecord(name, dns.ANY, classValue, 0);
	
}

void
doRequire(MyStringTokenizer st) throws IOException {
	dnsRecord rec;

	String qualifier = st.nextToken();
	if (qualifier.equals("-r")) 
		rec = parseRR(st, defaultClass, 0);
	else if (qualifier.equals("-s"))
		rec = parseRRExistence(st, dns.ANY);
	else if (qualifier.equals("-n"))
		rec = parseName(st, dns.ANY);
	else {
		System.out.println("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(PREREQ, rec);
		System.out.println(rec);
	}
}

void
doProhibit(MyStringTokenizer st) throws IOException {
	dnsRecord rec;

	String qualifier = st.nextToken();
	if (qualifier.equals("-r")) 
		rec = parseRR(st, defaultClass, 0);
	else if (qualifier.equals("-s"))
		rec = parseRRExistence(st, dns.NONE);
	else if (qualifier.equals("-n"))
		rec = parseName(st, dns.NONE);
	else {
		System.out.println("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(PREREQ, rec);
		System.out.println(rec);
	}
}

void
doAdd(MyStringTokenizer st) throws IOException {
	dnsRecord rec;

	String qualifier = st.nextToken();
	if (!qualifier.startsWith("-")) {
		st.putBackToken(qualifier);
		qualifier = "-r";
	}
	if (qualifier.equals("-r"))
		rec = parseRR(st, defaultClass, defaultTTL);
	else {
		System.out.println("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(UPDATE, rec);
		System.out.println(rec);
	}
}

void
doDelete(MyStringTokenizer st) throws IOException {
	dnsRecord rec;

	String qualifier = st.nextToken();
	if (qualifier.equals("-r"))
		rec = parseRR(st, dns.NONE, 0);
	else if (qualifier.equals("-s"))
		rec = parseRRExistence(st, dns.ANY);
	else if (qualifier.equals("-n"))
		rec = parseName(st, dns.ANY);
	else {
		System.out.println("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(UPDATE, rec);
		System.out.println(rec);
	}
}

void
doGlue(MyStringTokenizer st) throws IOException {
	dnsRecord rec;

	String qualifier = st.nextToken();
	if (!qualifier.startsWith("-")) {
		st.putBackToken(qualifier);
		qualifier = "-r";
	}
	if (qualifier.equals("-r"))
		rec = parseRR(st, defaultClass, defaultTTL);
	else {
		System.out.println("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(ADDITIONAL, rec);
		System.out.println(rec);
	}
}

static void
helpResolver() {
	System.out.println("Resolver options:\n" +

	  "    server <name>" +
	  "\tserver that receives the updates (default: localhost)\n" +

	  "    key <name> <data>" +
	  "\tTSIG key used to sign the messages\n" +

	  "    port <port>" +
	  "\t\tUDP/TCP port the message is sent to (default: 53)\n" +

	  "    tcp" +
	  "\t\t\tTCP should be used to send messages (default: unset)\n"
	);
}

static void
helpAttributes() {
	System.out.println("Attributes:\n" +

	  "    class <class>\t" +
	  "class of the zone to be updated (default: IN)\n" +

	  "    ttl <ttl>\t\t" +
	  "ttl of an added record, if unspecified (default: 0)\n" +

	  "    origin <origin>\t" +
	  "default origin of each record name (default: .)\n"
	);
};

static void
helpData() {
	System.out.println("Data:\n" +

	  "    require/prohibit\t" +
	  "require that a record, set, or name is/is not present\n" +
	  "\t-r <name> [ttl] [class] <type> <data ...> \n" +
	  "\t-s <name> <type> \n" +
	  "\t-n <name> \n\n" +

	  "    add\t\t" +
	  "specify a record to be added\n" +
	  "\t[-r] <name> [ttl] [class] <type> <data ...> \n\n" +

	  "    delete\t" +
	  "specify a record, set, or all records at a name to be deleted\n" +
	  "\t-r <name> [ttl] [class] <type> <data ...> \n" +
	  "\t-s <name> <type> \n" +
	  "\t-n <name> \n\n" +

	  "    glue\t" +
	  "specify an additional record\n" +
	  "\t[-r] <name> [ttl] [class] <type> <data ...> \n"
	);
}

static void
helpOperations() {
	System.out.println("Operations:\n" +
	  "    help [topic]\t" +
	  "this information\n" +

	  "    send\t\t" +
	  "sends the update and resets the current query\n" +

	  "    quit\t\t" +
	  "quits the program\n"
	);
}

static void
help(String topic) {
	if (topic != null) {
		if (topic.equalsIgnoreCase("resolver"))
			helpResolver();
		else if (topic.equalsIgnoreCase("attributes"))
			helpAttributes();
		else if (topic.equalsIgnoreCase("data"))
			helpData();
		else if (topic.equalsIgnoreCase("operations"))
			helpOperations();
		else
			System.out.println ("Topic " + topic + " unrecognized");
		return;
	}

	System.out.println("The help topics are:\n" +
	  "    Resolver\t" +
	  "Properties of the resolver and DNS\n" +

	  "    Attributes\t" +
	  "Properties of some/all records\n" +

	  "    Data\t" +
	  "Prerequisites, updates, and additional records\n" +

	  "    Operations\t" +
	  "Actions to be taken\n"
	);
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
