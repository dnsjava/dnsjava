// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import org.xbill.DNS.utils.*;
import org.xbill.Task.*;

/**
 * An implementation of Resolver that sends one query to one server.
 * SimpleResolver handles TCP retries, transaction security (TSIG), and
 * EDNS0.
 * @see Resolver
 * @see TSIG
 * @see OPTRecord
 *
 * @author Brian Wellington
 */


public class SimpleResolver implements Resolver {

/** The default port to send queries to */
public static final int DEFAULT_PORT = 53;

private InetAddress addr;
private int port = DEFAULT_PORT;
private boolean useTCP, ignoreTruncation;
private byte EDNSlevel = -1;
private TSIG tsig;
private int timeoutValue = 10 * 1000;

private static String defaultResolver = "localhost";
private static int uniqueID = 0;

/**
 * Creates a SimpleResolver that will query the specified host 
 * @exception UnknownHostException Failure occurred while finding the host
 */
public
SimpleResolver(String hostname) throws UnknownHostException {
	if (hostname == null) {
		hostname = FindServer.server();
		if (hostname == null)
			hostname = defaultResolver;
	}
	if (hostname.equals("0"))
		addr = InetAddress.getLocalHost();
	else
		addr = InetAddress.getByName(hostname);
}

/**
 * Creates a SimpleResolver.  The host to query is either found by
 * FindServer, or the default host is used.
 * @see FindServer
 * @exception UnknownHostException Failure occurred while finding the host
 */
public
SimpleResolver() throws UnknownHostException {
	this(null);
}

/** Sets the default host (initially localhost) to query */
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
	if (level != 0 && level != -1)
		throw new UnsupportedOperationException("invalid EDNS level " +
							"- must be 0 or -1");
	this.EDNSlevel = (byte) level;
}

public void
setTSIGKey(Name name, byte [] key) {
	tsig = new TSIG(name, key);
}

public void
setTSIGKey(String name, String key) {
	byte [] keyArray;
	Name keyname;
	if (key.length() > 1 && key.charAt(0) == ':')
		keyArray = base16.fromString(key.substring(1));
	else
		keyArray = base64.fromString(key);
	if (keyArray == null)
		throw new IllegalArgumentException("Invalid TSIG key string");
	try {
		keyname = Name.fromString(name, Name.root);
	}
	catch (TextParseException e) {
		throw new IllegalArgumentException("Invalid TSIG key name");
	}
	setTSIGKey(keyname, keyArray);
}

public void
setTSIGKey(String key) throws UnknownHostException {
	setTSIGKey(InetAddress.getLocalHost().getHostName(), key);
}

public void
setTimeout(int secs) {
	timeoutValue = secs * 1000;
}

private Message
sendTCP(Message query, byte [] out) throws IOException {
	byte [] in;
	Socket s;
	int inLength;
	DataInputStream dataIn;
	DataOutputStream dataOut;
	Message response;

	s = new Socket(addr, port);

	try {
		dataOut = new DataOutputStream(s.getOutputStream());
		dataOut.writeShort(out.length);
		dataOut.write(out);
		s.setSoTimeout(timeoutValue);

		try {
			dataIn = new DataInputStream(s.getInputStream());
			inLength = dataIn.readUnsignedShort();
			in = new byte[inLength];
			dataIn.readFully(in);
			if (Options.check("verbosemsg"))
				System.err.println(hexdump.dump("in", in));
		}
		catch (IOException e) {
			if (Options.check("verbose")) {
				System.err.println(";;" + e);
				System.err.println(";; No response");
			}
			throw e;
		}
	}
	finally {
		s.close();
	}

	try {
		response = new Message(in);
	}
	catch (IOException e) {
		throw new WireParseException("Error parsing message");
	}
	if (tsig != null) {
		response.TSIGsigned = true;
		byte error = tsig.verify(response, in, query.getTSIG());
		boolean ok = (error == Rcode.NOERROR);
		if (Options.check("verbose"))
			System.err.println("TSIG verify: " +
					   Rcode.string(error));
		response.TSIGverified = ok;
	}
	return response;
}

/**
 * Sends a message to a single server and waits for a response.
 * @param query The query to send.
 * @return The response.
 * @throws IOException An error occurred while sending or receiving.
 */
public Message
send(Message query) throws IOException {
	byte [] out, in;
	Message response;
	DatagramSocket s;
	DatagramPacket dp;
	short udpLength = 512;
	OPTRecord opt;
	byte edns;

	if (Options.check("verbose"))
		System.err.println("Sending to " + addr.getHostAddress() +
				   ":" + port);

	if (query.getQuestion().getType() == Type.AXFR)
		return sendAXFR(query);

	query = (Message) query.clone();
	opt = query.getOPT();
	if (opt != null) {
		edns = (byte) opt.getVersion();
		udpLength = opt.getPayloadSize();
	} else if (EDNSlevel >= 0) {
		edns = EDNSlevel;
		udpLength = 1280;
		opt = new OPTRecord(udpLength, Rcode.NOERROR, edns);
		query.addRecord(opt, Section.ADDITIONAL);
	}

	if (tsig != null)
		tsig.apply(query, null);

	out = query.toWire();
	if (Options.check("verbosemsg"))
		System.err.println(hexdump.dump("out", out));

	if (useTCP || out.length > udpLength)
		return sendTCP(query, out);

	s = new DatagramSocket();

	try {
		s.send(new DatagramPacket(out, out.length, addr, port));

		dp = new DatagramPacket(new byte[udpLength], udpLength);
		s.setSoTimeout(timeoutValue);
		try {
			s.receive(dp);
		}
		catch (IOException e) {
			if (Options.check("verbose")) {
				System.err.println(";;" + e);
				System.err.println(";; No response");
			}
			throw e;
		}
	}
	finally {
		s.close();
	}
	in = new byte [dp.getLength()];
	System.arraycopy(dp.getData(), 0, in, 0, in.length);
	if (Options.check("verbosemsg"))
		System.err.println(hexdump.dump("in", in));
	try {
		response = new Message(in);
	}
	catch (IOException e) {
		if (Options.check("verbose"))
			e.printStackTrace();
		throw new WireParseException("Error parsing message");
	}
	if (tsig != null) {
		response.TSIGsigned = true;
		byte error = tsig.verify(response, in, query.getTSIG());
		boolean ok = (error == Rcode.NOERROR);
		if (Options.check("verbose"))
			System.err.println("TSIG verify: " +
					   Rcode.string(error));
		response.TSIGverified = ok;
	}

	if (response.getHeader().getFlag(Flags.TC) && !ignoreTruncation)
		return sendTCP(query, out);
	else
		return response;
}

/**
 * Asynchronously sends a message to a single server, registering a listener
 * to receive a callback on success or exception.  Multiple asynchronous
 * lookups can be performed in parallel.  Since the callback may be invoked
 * before the function returns, external synchronization is necessary.
 * @param query The query to send
 * @param listener The object containing the callbacks.
 * @return An identifier, which is also a parameter in the callback
 */
public Object
sendAsync(final Message query, final ResolverListener listener) {
	final Object id;
	synchronized (this) {
		id = new Integer(uniqueID++);
	}
	String name = this.getClass() + ": " + query.getQuestion().getName();
	WorkerThread.assignThread(new ResolveThread(this, query, id, listener),
				  name);
	return id;
}

private Message
sendAXFR(Message query) throws IOException {
	byte [] out, in;
	Socket s;
	int inLength;
	DataInputStream dataIn;
	int soacount = 0;
	Message m, response;
	boolean first = true;

	s = new Socket(addr, port);

	try {
		query = (Message) query.clone();
		if (tsig != null)
			tsig.apply(query, null);

		out = query.toWire();
		if (Options.check("verbosemsg"))
			System.err.println(hexdump.dump("out", out));
		OutputStream sOut = s.getOutputStream();
		new DataOutputStream(sOut).writeShort(out.length);
		sOut.write(out);
		s.setSoTimeout(timeoutValue);

		response = new Message();
		response.getHeader().setID(query.getHeader().getID());
		if (tsig != null) {
			tsig.verifyAXFRStart();
			response.TSIGsigned = true;
			response.TSIGverified = true;
		}
		while (soacount < 2) {
			try {
				InputStream sIn = s.getInputStream();
				dataIn = new DataInputStream(sIn);
				inLength = dataIn.readUnsignedShort();
				in = new byte[inLength];
				dataIn.readFully(in);
			}
			catch (IOException e) {
				if (Options.check("verbose")) {
					System.err.println(";;" + e);
					System.err.println(";; No response");
				}
				throw e;
			}
			if (Options.check("verbosemsg"))
				System.err.println(hexdump.dump("in", in));
			try {
				m = new Message(in);
			}
			catch (IOException e) {
				throw new WireParseException
						("Error parsing message");
			}
			if (m.getHeader().getRcode() != Rcode.NOERROR) {
				if (soacount == 0)
					return m;
				if (Options.check("verbosemsg")) {
					System.err.println("Invalid AXFR packet: ");
					System.err.println(m);
				}
				throw new WireParseException
					("Invalid AXFR message");
			}
			if (m.getHeader().getCount(Section.QUESTION) > 1 ||
			    m.getHeader().getCount(Section.ANSWER) <= 0 ||
			    m.getHeader().getCount(Section.AUTHORITY) != 0)
			{
				if (Options.check("verbosemsg")) {
					System.err.println("Invalid AXFR packet: ");
					System.err.println(m);
				}
				throw new WireParseException
						("Invalid AXFR message");
			}
			for (int i = 1; i < 4; i++) {
				Record [] records = m.getSectionArray(i);
				for (int j = 0; j < records.length; j++) {
					response.addRecord(records[j], i);
					if (records[j] instanceof SOARecord)
						soacount++;
				}
			}
			if (tsig != null) {
				boolean required = (soacount > 1 || first);
				byte error = tsig.verifyAXFR(m, in,
							     query.getTSIG(),
							     required, first);
				boolean ok = (error == Rcode.NOERROR);
				if (!ok)
					response.TSIGverified = false;
				if (Options.check("verbose")) {
					String status;
					if (m.getTSIG() == null) {
						if (!ok)
							status = "expected";
						else
							status = "<>";
					}
					else {
						if (!ok)
							status = "failed";
						else
							status = "ok";
					}
					System.err.println("TSIG verify: " +
							   status);
				}
			}
			first = false;
		}
	}
	finally {
		s.close();
	}
	return response;
}

}
