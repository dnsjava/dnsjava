import java.util.*;
import java.io.*;
import java.net.*;

public class dnsResolver {

InetAddress addr;
int port = dns.PORT;
dnsTSIG TSIG;
int timeoutValue = 60 * 1000;

public dnsResolver(String hostname) {
	try {
		addr = InetAddress.getByName(hostname);
	}
	catch (UnknownHostException e) {
		System.out.println("Unknown host " + hostname);
		return;
	}
}

public void
setPort(int port) {
	this.port = port;
}

public void
setTSIGKey(String name, String key) {
	byte [] keyArray = base64.fromString(key);
	if (keyArray == null) {
		System.out.println("Invalid TSIG key string");
		return;
	}
	TSIG = new dnsTSIG(name, keyArray);
}

public void
setTSIGKey(String key) {
	String name;
	try {
		name = InetAddress.getLocalHost().getHostName();
	}
	catch (UnknownHostException e) {
		System.out.println("getLocalHost failed");
		return;
	}
	setTSIGKey(name, key);
}

dnsMessage
sendTCP(dnsMessage query, byte [] out) throws IOException {
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
	s.setSoTimeout(timeoutValue);

	try {
		dataIn = new DataInputStream(s.getInputStream());
		inLength = dataIn.readUnsignedShort();
		in = new byte[inLength];
		dataIn.readFully(in);
	}
	catch (InterruptedIOException e) {
		s.close();
		System.out.println(";; No response");
		return null;
	}

	s.close();
	dnsMessage response = new dnsMessage(in);
	if (TSIG != null) {
		boolean ok = TSIG.verify(response, in, query.getTSIG());
		System.out.println("TSIG verify: " + ok);
	}
	return response;
}

public dnsMessage
send(dnsMessage query) throws IOException {
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
	s.setSoTimeout(timeoutValue);
	try {
		s.receive(dp);
	}
	catch (InterruptedIOException e) {
		s.close();
		System.out.println(";; No response");
		return null;
	}
	in = new byte [dp.getLength()];
	System.arraycopy(dp.getData(), 0, in, 0, in.length);
	response = new dnsMessage(in);
	if (TSIG != null) {
		boolean ok = TSIG.verify(response, in, query.getTSIG());
		System.out.println(";; TSIG verify: " + ok);
	}

	s.close();
	if (response.getHeader().getFlag(dns.TC))
		return sendTCP(query, out);
	else
		return response;
}

public dnsMessage
sendAXFR(dnsMessage query) throws IOException {
	byte [] out, in;
	Socket s;
	int inLength;
	DataInputStream dataIn;
	int soacount = 0;
	dnsMessage response;
	boolean first = true;

	try {
		s = new Socket(addr, dns.PORT);
	}
	catch (SocketException e) {
		System.out.println(e);
		return null;
	}

	if (TSIG != null)
		TSIG.apply(query);

	out = query.toBytes();
	new DataOutputStream(s.getOutputStream()).writeShort(out.length);
	s.getOutputStream().write(out);
	s.setSoTimeout(timeoutValue);

	response = new dnsMessage();
	response.getHeader().setID(query.getHeader().getID());
	if (TSIG != null)
		TSIG.verifyAXFRStart();
	while (soacount < 2) {
		try {
			dataIn = new DataInputStream(s.getInputStream());
			inLength = dataIn.readUnsignedShort();
			in = new byte[inLength];
			dataIn.readFully(in);
		}
		catch (InterruptedIOException e) {
			s.close();
			System.out.println(";; No response");
			return null;
		}
		dnsMessage m = new dnsMessage(in);
		if (m.getHeader().getCount(dns.QUESTION) != 0 ||
		    m.getHeader().getCount(dns.ANSWER) <= 0 ||
		    m.getHeader().getCount(dns.AUTHORITY) != 0)
		{
			StringBuffer sb = new StringBuffer();
			sb.append("Invalid AXFR: ");
			for (int i=0; i < 4; i++) {
				Enumeration e = m.getSection(i).elements();
				System.out.println("--");
				while (e.hasMoreElements()) {
					dnsRecord r;
					r = (dnsRecord)e.nextElement();
					System.out.println(r);
				}
				System.out.println();
			}
			System.out.println(sb.toString());
			s.close();
			return null;
		}
		for (int i = 1; i < 4; i++) {
			Enumeration e = m.getSection(i).elements();
			while (e.hasMoreElements()) {
				dnsRecord r = (dnsRecord)e.nextElement();
				response.addRecord(i, r);
				if (r instanceof dnsSOARecord)
					soacount++;
			}
		}
		if (TSIG != null) {
			boolean required = (soacount > 1 || first);
			boolean ok = TSIG.verifyAXFR(m, in, query.getTSIG(),
						     required, first);
			System.out.println("TSIG verify: " + ok);
		}
		first = false;
	}

	s.close();
	return response;
}

}
