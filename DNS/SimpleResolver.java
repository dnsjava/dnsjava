// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import DNS.utils.*;

public class SimpleResolver implements Resolver {

public static final int PORT = 53;

private InetAddress addr;
private int port = PORT;
private boolean useTCP, ignoreTruncation;
private int EDNSlevel = -1;
private TSIG tsig;
private int timeoutValue = 60 * 1000;

static String defaultResolver = "localhost";

public
SimpleResolver(String hostname) throws UnknownHostException {
	if (hostname == null) {
		hostname = FindServer.server();
		if (hostname == null)
			hostname = defaultResolver;
	}
	addr = InetAddress.getByName(hostname);
}

public
SimpleResolver() throws UnknownHostException {
	this(null);
}

public static void
setDefaultResolver(String hostname) {
	defaultResolver = hostname;
}

public void
setPort(int port) {
	this.port = port;
}

public void
setTCP(boolean flag) {
	this.useTCP = flag;
}

public void
setIgnoreTruncation(boolean flag) {
	this.ignoreTruncation = flag;
}

public void
setEDNS(int level) {
	this.EDNSlevel = level;
}

public void
setTSIGKey(String name, String key) {
	byte [] keyArray = base64.fromString(key);
	if (keyArray == null) {
		System.out.println("Invalid TSIG key string");
		return;
	}
	tsig = new TSIG(name, keyArray);
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

public void
setTimeout(int secs) {
	timeoutValue = secs * 1000;
}

Message
sendTCP(Message query, byte [] out) throws IOException {
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
	catch (IOException e) {
		s.close();
		System.out.println(";; No response");
		return null;
	}

	s.close();
	Message response = new Message(in);
	if (tsig != null) {
		boolean ok = tsig.verify(response, in, query.getTSIG());
		System.out.println(";; TSIG verify: " + ok);
	}
	return response;
}

public Message
send(Message query) {
	byte [] out, in;
	Message response;
	DatagramSocket s;
	DatagramPacket dp;
	int udpLength = 512;

	try {
		try {
			s = new DatagramSocket();
		}
		catch (SocketException e) {
			System.out.println(e);
			return null;
		}

		query = (Message) query.clone();
		if (EDNSlevel >= 0) {
			udpLength = 1280;
			query.addRecord(Section.ADDITIONAL,
					EDNS.newOPT(udpLength));
		}

		if (tsig != null)
			tsig.apply(query, null);


		out = query.toWire();

		if (useTCP)
			return sendTCP(query, out);

		s.send(new DatagramPacket(out, out.length, addr, port));

		dp = new DatagramPacket(new byte[udpLength], udpLength);
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
		response = new Message(in);
		if (tsig != null) {
			boolean ok = tsig.verify(response, in, query.getTSIG());
			System.out.println(";; TSIG verify: " + ok);
		}

		s.close();
		if (response.getHeader().getFlag(Flags.TC) && !ignoreTruncation)
			return sendTCP(query, out);
		else
			return response;
	}
	catch (IOException e) {
		return null;
	}
}

private int
uniqueID(Message m) {
	Record r = m.getQuestion();
	return (((r.getName().hashCode() & 0xFFFF) << 16) +
		(r.getType() << 8) +
		(hashCode() & 0xFF));
}

public int
sendAsync(final Message query, final ResolverListener listener) {
	final int id = uniqueID(query);
	WorkerThread.assignThread(this, query, id, listener);
	return id;
}

public Message
sendAXFR(Message query) {
	byte [] out, in;
	Socket s;
	int inLength;
	DataInputStream dataIn;
	int soacount = 0;
	Message response;
	boolean first = true;

	try {
		try {
			s = new Socket(addr, port);
		}
		catch (SocketException e) {
			System.out.println(e);
			return null;
		}

		query = (Message) query.clone();
		if (tsig != null)
			tsig.apply(query, null);

		out = query.toWire();
		OutputStream sOut = s.getOutputStream();
		new DataOutputStream(sOut).writeShort(out.length);
		sOut.write(out);
		s.setSoTimeout(timeoutValue);

		response = new Message();
		response.getHeader().setID(query.getHeader().getID());
		if (tsig != null)
			tsig.verifyAXFRStart();
		while (soacount < 2) {
			try {
				InputStream sIn = s.getInputStream();
				dataIn = new DataInputStream(sIn);
				inLength = dataIn.readUnsignedShort();
				in = new byte[inLength];
				dataIn.readFully(in);
			}
			catch (IOException e) {
				s.close();
				System.out.println(";; No response");
				return null;
			}
			Message m = new Message(in);
			if (m.getHeader().getCount(Section.QUESTION) != 0 ||
			    m.getHeader().getCount(Section.ANSWER) <= 0 ||
			    m.getHeader().getCount(Section.AUTHORITY) != 0)
			{
				StringBuffer sb = new StringBuffer();
				sb.append("Invalid AXFR: ");
				for (int i=0; i < 4; i++) {
					Enumeration e = m.getSection(i);
					System.out.println("--");
					while (e.hasMoreElements()) {
						Record r;
						r = (Record)e.nextElement();
						System.out.println(r);
					}
					System.out.println();
				}
				System.out.println(sb.toString());
				s.close();
				return null;
			}
			for (int i = 1; i < 4; i++) {
				Enumeration e = m.getSection(i);
				while (e.hasMoreElements()) {
					Record r = (Record)e.nextElement();
					response.addRecord(i, r);
					if (r instanceof SOARecord)
						soacount++;
				}
			}
			if (tsig != null) {
				boolean required = (soacount > 1 || first);
				boolean ok = tsig.verifyAXFR(m, in, query.getTSIG(),
							     required, first);
				System.out.println("TSIG verify: " + ok);
			}
			first = false;
		}
		s.close();
		return response;
	}
	catch (IOException e) {
		return null;
	}
}

}
