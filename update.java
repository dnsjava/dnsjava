// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.net.*;
import java.io.*;
import java.util.*;
import org.xbill.DNS.*;
import org.xbill.DNS.utils.*;

/** @author Brian Wellington &lt;bwelling@xbill.org&gt; */

public class update {

Message query, response;
Resolver res;
String server = null;
Name origin, zone;
int defaultTTL;
short defaultClass = DClass.IN;
PrintStream log = null;

void
print(Object o) {
	System.out.println(o);
	if (log != null)
		log.println(o);
}

public
update(InputStream in) throws IOException {
	Vector inputs = new Vector();
	Vector istreams = new Vector();

	query = new Message();
	query.getHeader().setOpcode(Opcode.UPDATE);

	InputStreamReader isr = new InputStreamReader(in);
	BufferedReader br = new BufferedReader(isr);

	inputs.addElement(br);
	istreams.addElement(in);

	while (true) {
		try {
			String line = null;
			do {
				InputStream is;
				is = (InputStream) istreams.lastElement();
				br = (BufferedReader)inputs.lastElement();

				if (is == System.in)
					System.out.print("> ");

				line = Master.readExtendedLine(br);
				if (line == null) {
					br.close();
					inputs.removeElement(br);
					istreams.removeElement(is);
					if (inputs.isEmpty())
						return;
				}
			} while (line == null);

			if (log != null)
				log.println("> " + line);

			if (line.length() == 0 || line.charAt(0) == '#')
				continue;

			MyStringTokenizer st = new MyStringTokenizer(line);
			if (!st.hasMoreTokens())
				continue;
			String operation = st.nextToken();

			if (operation.equals("server")) {
				server = st.nextToken();
				res = new SimpleResolver(server);
			}

			else if (operation.equals("key")) {
				String keyname = st.nextToken();
				String keydata = st.nextToken();
				if (res == null)
					res = new SimpleResolver(server);
				res.setTSIGKey(keyname, keydata);
			}

			else if (operation.equals("port")) {
				if (res == null)
					res = new SimpleResolver(server);
				res.setPort(Short.parseShort(st.nextToken()));
			}

			else if (operation.equals("tcp")) {
				if (res == null)
					res = new SimpleResolver(server);
				res.setTCP(true);
			}

			else if (operation.equals("class")) {
				String s = st.nextToken();
				short newClass = DClass.value(s);
				if (newClass > 0)
					defaultClass = newClass;
				else
					print("Invalid class " + newClass);
			}

			else if (operation.equals("ttl"))
				defaultTTL = TTL.parseTTL(st.nextToken());

			else if (operation.equals("origin"))
				origin = new Name(st.nextToken());

			else if (operation.equals("zone"))
				zone = new Name(st.nextToken());

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

			else if (operation.equals("echo"))
				print(line.substring(4).trim());

			else if (operation.equals("send")) {
				if (res == null)
					res = new SimpleResolver(server);
				sendUpdate();
				query = new Message();
				query.getHeader().setOpcode(Opcode.UPDATE);
			}

			else if (operation.equals("query"))
				doQuery(st);

			else if (operation.equals("quit") ||
				 operation.equals("q"))
			{
				if (log != null)
					log.close();
				Enumeration e = inputs.elements();
				while (e.hasMoreElements()) {
					BufferedReader tbr;
					tbr = (BufferedReader) e.nextElement();
					tbr.close();
				}
				System.exit(0);
			}

			else if (operation.equals("file"))
				doFile(st, inputs, istreams);

			else if (operation.equals("log"))
				doLog(st);

			else if (operation.equals("assert")) {
				if (doAssert(st) == false)
					return;
			}

			else
				print("invalid keyword: " + operation);
		}
		catch (NullPointerException npe) {
			System.out.println("Parse error");
		}
		catch (InterruptedIOException iioe) {
			System.out.println("Operation timed out");
		}
	}
}

void
sendUpdate() throws IOException {
	if (query.getHeader().getCount(Section.ZONE) == 0) {
		Name updzone;
		if (zone != null)
			updzone = zone;
		else
			updzone = origin;
		short dclass = defaultClass;
		if (updzone == null) {
			Enumeration updates = query.getSection(Section.UPDATE);
			if (updates == null) {
				print("Invalid update");
				return;
			}
			Record r = (Record) updates.nextElement();
			updzone = new Name(r.getName(), 1);
			dclass = r.getDClass();
		}
		Record soa = Record.newRecord(updzone, Type.SOA, dclass);
		query.addRecord(soa, Section.ZONE);
	}

	response = res.send(query);
	if (response == null)
		return;

	print(response);
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
		ttl = TTL.parseTTL(s);
		s = st.nextToken();
	}
	catch (NumberFormatException e) {
		ttl = TTLValue;
	}

	if (DClass.value(s) >= 0)
		s = st.nextToken();

	if ((type = Type.value(s)) < 0)
		/* Close enough... */
		throw new NullPointerException("Parse error");

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
		print("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(rec, Section.PREREQ);
		print(rec);
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
		print("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(rec, Section.PREREQ);
		print(rec);
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
		print("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(rec, Section.UPDATE);
		print(rec);
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
		print("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(rec, Section.UPDATE);
		print(rec);
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
		print("qualifier " + qualifier + " not supported");
		return;
	}
	if (rec != null) {
		query.addRecord(rec, Section.ADDITIONAL);
		print(rec);
	}
}

void
doQuery(MyStringTokenizer st) throws IOException {
	Record rec;

	Name name = null;
	short type = Type.A, dclass = defaultClass;

	name = new Name(st.nextToken(), origin);
	if (st.hasMoreTokens()) {
		type = Type.value(st.nextToken());
		if (type < 0)
			throw new IOException("Invalid type");
		if (st.hasMoreTokens()) {
			dclass = DClass.value(st.nextToken());
			if (dclass < 0)
				throw new IOException("Invalid class");
		}
	}

	rec = Record.newRecord(name, type, dclass);
	Message newQuery = Message.newQuery(rec);
	if (res == null)
		res = new SimpleResolver(server);
	if (rec.getType() == Type.AXFR)
		response = res.sendAXFR(newQuery);
	else
		response = res.send(newQuery);
	print(response);
}

void
doFile(MyStringTokenizer st, Vector inputs, Vector istreams) {
	String s = st.nextToken();
	try {
		InputStreamReader isr2;
		if (!s.equals("-")) {
			FileInputStream fis = new FileInputStream(s);
			isr2 = new InputStreamReader(fis);
			istreams.addElement(fis);
		}
		else {
			isr2 = new InputStreamReader(System.in);
			istreams.addElement(System.in);
		}
		BufferedReader br2 = new BufferedReader(isr2);
		inputs.addElement(br2);
	}
	catch (FileNotFoundException e) {
		print(s + "not found");
	}
	
}

void
doLog(MyStringTokenizer st) {
	String s = st.nextToken();
	try {
		FileOutputStream fos = new FileOutputStream(s);
		log = new PrintStream(fos);
	}
	catch (Exception e) {
		print("Error opening " + s);
	}
}

boolean
doAssert(MyStringTokenizer st) {
	String field = st.nextToken();
	String expected = st.nextToken();
	String value = null;
	boolean flag = true;
	int section;

	if (response == null) {
		print("No response has been received");
		return true;
	}
	if (field.equalsIgnoreCase("rcode")) {
		short rcode = response.getHeader().getRcode();
		if (rcode != Rcode.value(expected)) {
			value = Rcode.string(rcode);
			flag = false;
		}
	}
	else if (field.equalsIgnoreCase("serial")) {
		Record [] answers = response.getSectionArray(Section.ANSWER);
		if (answers.length < 1 || !(answers[0] instanceof SOARecord))
			print("Invalid response (no SOA)");
		else {
			SOARecord soa = (SOARecord) answers[0];
			int serial = soa.getSerial();
			if (serial != new Integer(expected).intValue()) {
				value = new Integer(serial).toString();
				flag = false;
			}
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
		print("Invalid assertion keyword: " + field);

	if (flag == false) {
		print("Expected " + field + " " + expected + 
		      ", received " + value);
		if (st.hasMoreTokens())
			print(st.nextToken());
	}
	return flag;
}

static void
helpResolver() {
	System.out.println("Resolver options:\n" +

	  "    server <name>" +
	  "\tserver that receives the updates\n" +

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
	  "default origin of each record name (default: .)\n" +

	  "    zone <zone>\t" +
	  "zone to update (default: value of <origin>)\n"
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

	  "    echo <text>\t\t" +
	  "echoes the line\n" +

	  "    send\t\t" +
	  "sends the update and resets the current query\n" +

	  "    query <name> <type> <class> \t" +
	  "issues a query for this name, type, and class\n" +

	  "    quit\t\t" +
	  "quits the program\n" +

	  "    file <file>\t\t" +
	  "opens the specified file as the new input source\n" +

	  "    log <file>\t\t" +
	  "opens the specified file and uses it to log output\n" +

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
