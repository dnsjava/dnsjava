import java.net.*;
import java.io.*;
import java.util.*;

public class update {

static final int ZONE = dns.QUERY;
static final int PREREQUISITE = dns.ANSWER;
static final int UPDATE = dns.AUTHORITY;
static final int ADDITIONAL = dns.ADDITIONAL;

static dnsName name = null;
static short type = dns.A, _class = dns.IN;

static void usage() {
	System.out.println("Usage: update @server name [-t ttl] [-p port] [-k key]");
	System.exit(0);
}

static void doUpdate(dnsMessage query, dnsResolver res) throws IOException {
	dnsMessage response;

	response = res.send(query);

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

public static void main(String argv[]) throws IOException {
	String server;
	dnsName name, domain;
	InetAddress addr;
	int ttl = 3600;
	dnsMessage query = new dnsMessage();
	dnsRecord soa, a;
	dnsResolver res = null;

	query.getHeader().setRandomID();
	query.getHeader().setOpcode(dns.UPDATE);

	if (argv.length < 2) {
		usage();
	}

	if (!argv[0].startsWith("@")) {
		usage();
	}
	server = argv[0].substring(1);
	res = new dnsResolver(server);
	name = new dnsName(argv[1]);

	for (int arg = 2; arg < argv.length; arg++) {
		if (!argv[arg].startsWith("-") || argv[arg].length() < 2)
			continue;
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
			String keyStr;
			if (argv[arg].length() > 2)
				keyStr = argv[arg].substring(2);
			else
				keyStr = argv[++arg];
			byte [] key = keyStr.getBytes();
			res.setTSIGKey(key);
			break;

		    case 't':
			ttl = Integer.parseInt(argv[arg]);
			if (ttl <= 0)
				ttl = 3600;
			break;

		    default:
			System.out.print("Invalid option" + argv[arg]);
		}
	}

	try {
		addr = InetAddress.getLocalHost();
	}
	catch (UnknownHostException e) {
		System.out.println(e);
		return;
	}

	domain = new dnsName(name, 1);
	soa = new dnsSOARecord(domain, dns.IN);
	a = new dnsARecord(name, dns.IN, ttl, addr);

	query.addRecord(ZONE, soa);
	query.addRecord(UPDATE, a);

	doUpdate(query, res);
}

}
