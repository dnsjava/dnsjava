import java.util.*;
import java.io.*;
import java.net.*;

public class dnsResolver {

InetAddress addr;
int port = dns.PORT;
dnsTSIG TSIG;

public dnsResolver(String hostname) {
	try {
		addr = InetAddress.getByName(hostname);
	}
	catch (UnknownHostException e) {
		System.out.println("Unknown host " + hostname);
		return;
	}
}

public void setPort(int port) {
	this.port = port;
}

public void setTSIGKey(byte [] key) {
	TSIG = new dnsTSIG(key);
}

dnsMessage sendTCP(dnsMessage query, byte [] out) throws IOException {
	byte [] in;
	Socket s;
	int inLength;
	DataInputStream dataIn;

	try {
		s = new Socket(addr, port);
	}
	catch (SocketException e) {
		System.out.println(e);
		return null;
	}

	new DataOutputStream(s.getOutputStream()).writeShort(out.length);
	s.getOutputStream().write(out);

	dataIn = new DataInputStream(s.getInputStream());
	inLength = dataIn.readUnsignedShort();
	in = new byte[inLength];
	dataIn.readFully(in);

	s.close();
	dnsMessage response = new dnsMessage(in);
	if (TSIG != null) {
		boolean ok = TSIG.verify(response, in, query.getTSIG());
		System.out.println("TSIG verify: " + ok);
	}
	return response;
}

public dnsMessage send(dnsMessage query) throws IOException {
	byte [] out, in;
	dnsMessage response;
	DatagramSocket s;
	DatagramPacket dp;

	try {
		s = new DatagramSocket();
	}
	catch (SocketException e) {
		System.out.println(e);
		return null;
	}

	if (TSIG != null)
		TSIG.apply(query);

	out = query.toBytes();
	s.send(new DatagramPacket(out, out.length, addr, port));

	dp = new DatagramPacket(new byte[512], 512);
	s.receive(dp);
	in = new byte [dp.getLength()];
	System.arraycopy(dp.getData(), 0, in, 0, in.length);
	response = new dnsMessage(in);
	if (TSIG != null) {
		boolean ok = TSIG.verify(response, in, query.getTSIG());
		System.out.println("TSIG verify: " + ok);
	}

	s.close();
	if (response.getHeader().getFlag(dns.TC))
		return sendTCP(query, out);
	else
		return response;
}

public dnsMessage sendAXFR(dnsMessage query) throws IOException {
	byte [] out, in;
	Socket s;
	int inLength;
	DataInputStream dataIn;
	int soacount = 0;
	dnsMessage response;

	try {
		s = new Socket(addr, dns.PORT);
	}
	catch (SocketException e) {
		System.out.println(e);
		return null;
	}

	out = query.toBytes();
	new DataOutputStream(s.getOutputStream()).writeShort(out.length);
	s.getOutputStream().write(out);

	response = new dnsMessage();
	response.getHeader().setID(query.getHeader().getID());
	while (true) {
		dataIn = new DataInputStream(s.getInputStream());
		inLength = dataIn.readUnsignedShort();
		in = new byte[inLength];
		dataIn.readFully(in);
		dnsMessage m = new dnsMessage(in);
		if (m.getHeader().getCount(dns.QUESTION) != 0 ||
		    m.getHeader().getCount(dns.ANSWER) <= 0 ||
		    m.getHeader().getCount(dns.AUTHORITY) != 0 ||
		    m.getHeader().getCount(dns.ADDITIONAL) != 0)
			throw new IOException("Invalid AXFR message");
		Vector v = m.getSection(dns.ANSWER);
		Enumeration e = v.elements();
		while (e.hasMoreElements()) {
			dnsRecord r = (dnsRecord)e.nextElement();
			response.addRecord(dns.ANSWER, r);
			if (r instanceof dnsSOARecord)
				soacount++;
		}
		if (soacount > 1)
			break;
	}

	s.close();
	return response;
}


}
