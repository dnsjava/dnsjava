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
	System.out.println("Usage: update @server name address [ttl]");
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
	int ttl;
	dnsMessage query = new dnsMessage();
	dnsRecord soa, a;
	dnsResolver res = null;

	query.getHeader().setRandomID();
	query.getHeader().setOpcode(dns.UPDATE);

	if (argv.length < 3) {
		usage();
	}

	if (!argv[0].startsWith("@")) {
		usage();
	}
	server = argv[0].substring(1);
	name = new dnsName(argv[1]);
	try {
		addr = InetAddress.getByName(argv[2]);
	}
	catch (UnknownHostException e) {
		System.out.println(e);
		return;
	}
	if (argv.length < 4 || (ttl = Integer.parseInt(argv[4])) <= 0)
		ttl = 3600;

	domain = new dnsName(name, 1);
	soa = new dnsSOARecord(domain, dns.IN);
	a = new dnsARecord(name, dns.IN, ttl, addr);

	query.addRecord(ZONE, soa);
	query.addRecord(UPDATE, a);

	res = new dnsResolver(server);
	doUpdate(query, res);
}

}
