// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.net.*;
import java.io.*;
import java.util.*;
import DNS.*;

public class update {

static final int ZONE = Section.QUESTION;
static final int PREREQ = Section.ANSWER;
static final int UPDATE = Section.AUTHORITY;
static final int ADDITIONAL = Section.ADDITIONAL;

Message query, response;
Resolver res;
String server = "localhost";
Name origin;
int defaultTTL;
short defaultClass = DClass.IN;

public
update(InputStream in) throws IOException {
	Vector inputs = new Vector();

	query = new Message();
	query.getHeader().setOpcode(Opcode.UPDATE);

	InputStreamReader isr = new InputStreamReader(in);
	BufferedReader br = new BufferedReader(isr);
	BufferedReader brOrig = br;

	inputs.addElement(br);

	while (true) {
		String line = null;
		do {
			br = (BufferedReader)inputs.lastElement();

			if (in == System.in && brOrig == br)
				System.out.print("> ");

			line = IO.readExtendedLine(br);
			if (line == null) {
				br.close();
				inputs.removeElement(br);
				if (inputs.isEmpty())
					return;
			}
		} while (line == null);

		MyStringTokenizer st = new MyStringTokenizer(line);
		if (!st.hasMoreTokens())
			continue;
		String operation = st.nextToken();

		if (operation.equals("#"))
			continue;

		else if (operation.equals("server")) {
			server = st.nextToken();
			res = new Resolver(server);
		}

		else if (operation.equals("key")) {
			String keyname = st.nextToken();
			String keydata = st.nextToken();
			if (res == null)
				res = new Resolver(server);
			res.setTSIGKey(keyname, keydata);
		}

		else if (operation.equals("port")) {
			if (res == null)
				res = new Resolver(server);
			res.setPort(Short.parseShort(st.nextToken()));
		}

		else if (operation.equals("tcp")) {
			if (res == null)
				res = new Resolver(server);
			res.setTCP(true);
		}

		else if (operation.equals("class")) {
			String s = st.nextToken();
			short newClass = DClass.value(s);
			if (newClass > 0)
				defaultClass = newClass;
			else
				System.out.println("Invalid class " + newClass);
		}

		else if (operation.equals("ttl"))
			defaultTTL = Integer.parseInt(st.nextToken());

		else if (operation.equals("origin"))
			origin = new Name(st.nextToken());

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
				res = new Resolver(server);
			sendUpdate();
			query = new Message();
			query.getHeader().setOpcode(Opcode.UPDATE);
		}

		else if (operation.equals("query"))
			doQuery(st);

		else if (operation.equals("quit") ||
			 operation.equals("q"))
			System.exit(0);

		else if (operation.equals("file"))
			doFile(st, inputs);

		else if (operation.equals("assert")) {
			if (doAssert(st) == false)
				return;
		}

		else
			System.out.println("invalid keyword: " + operation);
	}
}

void
sendUpdate() throws IOException {
	if (query.getHeader().getCount(ZONE) == 0) {
		Name zone = origin;
		short dclass = defaultClass;
		if (zone == null) {
			Enumeration updates = query.getSection(UPDATE);
			if (updates == null) {
				System.out.println("Invalid update");
				return;
			}
			Record r = (Record) updates.nextElement();
			zone = new Name(r.getName(), 1);
			dclass = r.getDClass();
		}
		Record soa = Record.newRecord(zone, Type.SOA, dclass);
		query.addRecord(ZONE, soa);
	}

	response = res.send(query);
	if (response == null)
		return;

	System.out.println(response);
	// System.out.println(response.getHeader());

	// System.out.println(";; done");
}

/* 
 * <name> [ttl] [class] <type> <data>
 * Ignore the class, if present.
 */
Record
parseRR(MyStringTokenizer st, short classValue, int TTLValue)
throws IOException
{
	Name name = new Name(st.nextToken(), origin);
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

	if (DClass.value(s) >= 0)
		s = st.nextToken();

	if ((type = Type.value(s)) < 0)
		throw new IOException("Parse error");

	return Record.fromString(name, type, classValue, ttl, st, origin);
}

/* 
 * <name> <type>
 */
Record
parseSet(MyStringTokenizer st, short classValue) throws IOException {
	Name name = new Name(st.nextToken(), origin);
	short type;

	if ((type = Type.value(st.nextToken())) < 0)
		throw new IOException("Parse error");

	return Record.newRecord(name, type, classValue, 0);
	
}

/* 
 * <name>
 */
Record
parseName(MyStringTokenizer st, short classValue) throws IOException {
	Name name = new Name(st.nextToken(), origin);

	return Record.newRecord(name, Type.ANY, classValue, 0);
	
}

void
doRequire(MyStringTokenizer st) throws IOException {
	Record rec;

	String qualifier = st.nextToken();
	if (qualifier.equals("-r")) 
		rec = parseRR(st, defaultClass, 0);
	else if (qualifier.equals("-s"))
		rec = parseSet(st, DClass.ANY);
	else if (qualifier.equals("-n"))
		rec = parseName(st, DClass.ANY);
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
	Record rec;

	String qualifier = st.nextToken();
	if (qualifier.equals("-r")) 
		rec = parseRR(st, defaultClass, 0);
	else if (qualifier.equals("-s"))
		rec = parseSet(st, DClass.NONE);
	else if (qualifier.equals("-n"))
		rec = parseName(st, DClass.NONE);
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
	Record rec;

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
	Record rec;

	String qualifier = st.nextToken();
	if (qualifier.equals("-r"))
		rec = parseRR(st, DClass.NONE, 0);
	else if (qualifier.equals("-s"))
		rec = parseSet(st, DClass.ANY);
	else if (qualifier.equals("-n"))
		rec = parseName(st, DClass.ANY);
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
	Record rec;

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

void
doQuery(MyStringTokenizer st) throws IOException {
	Record rec;
	Message newQuery = new Message();

	rec = parseSet(st, defaultClass);
	newQuery.getHeader().setOpcode(Opcode.QUERY);
	newQuery.getHeader().setFlag(Flags.RD);
	newQuery.addRecord(Section.QUESTION, rec);
	if (res == null)
		res = new Resolver(server);
	if (rec.getType() == Type.AXFR)
		response = res.sendAXFR(newQuery);
	else
		response = res.send(newQuery);
	System.out.println(response);
}

void
doFile(MyStringTokenizer st, Vector inputs) {
	String s = st.nextToken();
	try {
		FileInputStream fis = new FileInputStream(s);
		InputStreamReader isr2 = new InputStreamReader(fis);
		BufferedReader br2 = new BufferedReader(isr2);
		inputs.addElement(br2);
	}
	catch (FileNotFoundException e) {
		System.out.println(s + "not found");
		return;
	}
	
}

boolean
doAssert(MyStringTokenizer st) {
	String field = st.nextToken();
	String expected = st.nextToken();
	String value = null;
	boolean flag = true;
	int section;

	if (field.equalsIgnoreCase("rcode")) {
		short rcode = response.getHeader().getRcode();
		if (rcode != Rcode.value(expected)) {
			value = Rcode.string(rcode);
			flag = false;
		}
	}
	else if ((section = Section.value(field)) >= 0) {
		short count = response.getHeader().getCount(section);
		if (count != Short.parseShort(expected)) {
			value = new Short(count).toString();
			flag = false;
		}
	}
	else
		System.out.println("Invalid assertion keyword: " + field);

	if (flag == false) {
		System.out.println("Expected " + field + " " + expected + 
				   ", received " + value);
		if (st.hasMoreTokens())
			System.out.println(st.nextToken());
	}
	return flag;
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
	  "\t[-r] <name> [ttl] [class] <type> <data ...> \n\n" +

	  "    (notes: @ represents the origin " +
	  "and @me@ represents the local IP address)\n"
	);
}

static void
helpOperations() {
	System.out.println("Operations:\n" +
	  "    help [topic]\t" +
	  "this information\n" +

	  "    send\t\t" +
	  "sends the update and resets the current query\n" +

	  "    query <name> <type>\t" +
	  "issues a query for this name and type\n" +

	  "    quit\t\t" +
	  "quits the program\n" +

	  "    file <file>\t\t" +
	  "opens the specified file and uses it as the new input\n" +
	  "\t\t\tsource\n" +

	  "    assert <field> <value> [msg]\n" +
	  "\t\t\tasserts that the value of the field in the last response\n" +
	  "\t\t\tmatches the value specified.  If not, the message is\n" +
	  "\t\t\tprinted (if present) and the program exits.\n"
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

public static void
main(String args[]) throws IOException {

	InputStream in = null;
	if (args.length == 1) {
		try {
			in = new FileInputStream(args[0]);
		}
		catch (FileNotFoundException e) {
			System.out.println(args[0] + " not found.");
			System.exit(-1);
		}
	}
	else
		in = System.in;
	update u = new update(in);
}

}
