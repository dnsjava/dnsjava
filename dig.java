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
doQuery(Message response, long ms) throws IOException {
	System.out.println("; java dig 0.0");
	System.out.println(response);
	System.out.println(";; Query time: " + ms + " ms");
}

static void
doAXFR(Message response) throws IOException {
	System.out.println("; java dig 0.0 <> " + name + " axfr");
	if (response.isSigned()) {
		System.out.print(";; TSIG ");
		if (response.isVerified())
			System.out.println("ok");
		else
			System.out.println("failed");
	}

	if (response.getRcode() != Rcode.NOERROR) {
		System.out.println(response);
		return;
	}

	Record [] records = response.getSectionArray(Section.ANSWER);
	for (int i = 0; i < records.length; i++)
		System.out.println(records[i]);

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
	Message query, response;
	Record rec;
	Record opt = null;
	Resolver res = null;
	boolean printQuery = false;
	long startTime, endTime;

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
			name = Name.fromString(dns.inaddrString(argv[arg++]),
					       Name.root);
			type = Type.PTR;
			_class = DClass.IN;
		}
		else {
			name = Name.fromString(nameString, Name.root);
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
							   "EDNS level: " +
							   edns);
					return;
				}
				res.setEDNS(edns);
				break;

			    case 'd':
			    	opt = new OPTRecord((short)1280, (byte)0,
						    (byte)0, Flags.DO);
				break;

			    case 'q':
			    	printQuery = true;
				break;

			    default:
				System.out.print("Invalid option: ");
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
	if (opt != null)
		query.addRecord(opt, Section.ADDITIONAL);
	if (printQuery)
		System.out.println(query);
	startTime = System.currentTimeMillis();
	response = res.send(query);
	endTime = System.currentTimeMillis();

	if (type == Type.AXFR)
		doAXFR(response);
	else
		doQuery(response, endTime - startTime);
}

}
