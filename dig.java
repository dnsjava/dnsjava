// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;
import org.xbill.DNS.*;

/** @author Brian Wellington &lt;bwelling@xbill.org&gt; */

public class dig {

static Name name = null;
static short type = Type.A, _class = DClass.IN;

static void
usage() {
	System.out.println("Usage: dig [@server] name [<type>] [<class>] " +
			   "[options]");
	System.exit(0);
}

static void
doQuery(Message query, Resolver res) throws IOException {
	Message response;

	System.out.println("; java dig 0.0");

	response = res.send(query);
	if (response == null)
		return;

	System.out.println(response);
}

static void
doAXFR(Message query, Resolver res) throws IOException {
	Message response;

	System.out.println("; java dig 0.0 <> " + name + " axfr");

	response = res.sendAXFR(query);
	if (response == null)
		return;

	Enumeration e = response.getSection(Section.ANSWER);
	while (e.hasMoreElements())
		System.out.println(e.nextElement());

	System.out.print(";; done (");
	System.out.print(response.getHeader().getCount(Section.ANSWER));
	System.out.print(" records, ");
	System.out.print(response.getHeader().getCount(Section.ADDITIONAL));
	System.out.println(" additional)");
}

public static void
main(String argv[]) throws IOException {
	String server;
	int arg;
	Message query;
	Record rec;
	Resolver res = null;

	if (argv.length < 1) {
		usage();
	}

	try {
		arg = 0;
		if (argv[arg].startsWith("@")) {
			server = argv[arg++].substring(1);
			res = new SimpleResolver(server);
		}
		else
			res = new ExtendedResolver();

		String nameString = argv[arg++];
		if (nameString.equals("-x")) {
			name = new Name(dns.inaddrString(argv[arg++]));
			type = Type.PTR;
			_class = DClass.IN;
		}
		else {
			name = new Name(nameString);
			type = Type.value(argv[arg]);
			if (type < 0)
				type = Type.A;
			else
				arg++;

			_class = DClass.value(argv[arg]);
			if (_class < 0)
				_class = DClass.IN;
			else
				arg++;
		}

		while (argv[arg].startsWith("-") && argv[arg].length() > 1) {
			switch (argv[arg].charAt(1)) {
			    case 'p':
				String portStr;
				int port;
				if (argv[arg].length() > 2)
					portStr = argv[arg].substring(2);
				else
					portStr = argv[++arg];
				port = Integer.parseInt(portStr);
				if (port < 0 || port > 65536) {
					System.out.println("Invalid port");
					return;
				}
				res.setPort(port);
				break;

			    case 'k':
				String key;
				if (argv[arg].length() > 2)
					key = argv[arg].substring(2);
				else
					key = argv[++arg];
				int index = key.indexOf('/');
				if (index < 0)
					res.setTSIGKey(key);
				else
					res.setTSIGKey(key.substring(0, index),
						       key.substring(index+1));
				break;

			    case 't':
				res.setTCP(true);
				break;

			    case 'i':
				res.setIgnoreTruncation(true);
				break;

			    case 'e':
				String ednsStr;
				int edns;
				if (argv[arg].length() > 2)
					ednsStr = argv[arg].substring(2);
				else
					ednsStr = argv[++arg];
				edns = Integer.parseInt(ednsStr);
				if (edns < 0 || edns > 1) {
					System.out.println("Unsupported " +
							   "EDNS level " +
							   edns);
					return;
				}
				res.setEDNS(edns);
				break;

			    default:
				System.out.print("Invalid option");
				System.out.println(argv[arg]);
			}
			arg++;
		}

	}
	catch (ArrayIndexOutOfBoundsException e) {
		if (name == null)
			usage();
	}

	rec = Record.newRecord(name, type, _class);
	query = Message.newQuery(rec);

	if (type == Type.AXFR)
		doAXFR(query, res);
	else
		doQuery(query, res);
}

}
