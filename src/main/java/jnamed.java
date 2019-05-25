// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

import java.io.*;
import java.net.*;
import java.util.*;
import org.xbill.DNS.*;

/** @author Brian Wellington &lt;bwelling@xbill.org&gt; */

public class jnamed {

static final int FLAG_DNSSECOK = 1;
static final int FLAG_SIGONLY = 2;

Map caches;
Map znames;
Map TSIGs;

private static String
addrport(InetAddress addr, int port) {
	return addr.getHostAddress() + "#" + port;
}

public
jnamed(String conffile) throws IOException, ZoneTransferException {
	FileInputStream fs;
	InputStreamReader isr;
	BufferedReader br;
	List ports = new ArrayList();
	List addresses = new ArrayList();
	try {
		fs = new FileInputStream(conffile);
		isr = new InputStreamReader(fs);
		br = new BufferedReader(isr);
	}
	catch (Exception e) {
		System.out.println("Cannot open " + conffile);
		return;
	}

	try {
		caches = new HashMap();
		znames = new HashMap();
		TSIGs = new HashMap();

		String line = null;
		while ((line = br.readLine()) != null) {
			StringTokenizer st = new StringTokenizer(line);
			if (!st.hasMoreTokens())
				continue;
			String keyword = st.nextToken();
			if (!st.hasMoreTokens()) {
				System.out.println("Invalid line: " + line);
				continue;
			}
			if (keyword.charAt(0) == '#')
				continue;
			if (keyword.equals("primary"))
				addPrimaryZone(st.nextToken(), st.nextToken());
			else if (keyword.equals("secondary"))
				addSecondaryZone(st.nextToken(),
						 st.nextToken());
			else if (keyword.equals("cache")) {
				Cache cache = new Cache(st.nextToken());
				caches.put(new Integer(DClass.IN), cache);
			} else if (keyword.equals("key")) {
				String s1 = st.nextToken();
				String s2 = st.nextToken();
				if (st.hasMoreTokens())
					addTSIG(s1, s2, st.nextToken());
				else
					addTSIG("hmac-md5", s1, s2);
			} else if (keyword.equals("port")) {
				ports.add(Integer.valueOf(st.nextToken()));
			} else if (keyword.equals("address")) {
				String addr = st.nextToken();
				addresses.add(Address.getByAddress(addr));
			} else {
				System.out.println("unknown keyword: " +
						   keyword);
			}

		}

		if (ports.size() == 0)
			ports.add(new Integer(53));

		if (addresses.size() == 0)
			addresses.add(Address.getByAddress("0.0.0.0"));

		Iterator iaddr = addresses.iterator();
		while (iaddr.hasNext()) {
			InetAddress addr = (InetAddress) iaddr.next();
			Iterator iport = ports.iterator();
			while (iport.hasNext()) {
				int port = ((Integer)iport.next()).intValue();
				addUDP(addr, port);
				addTCP(addr, port);
				System.out.println("jnamed: listening on " +
						   addrport(addr, port));
			}
		}
		System.out.println("jnamed: running");
	}
	finally {
		fs.close();
	}
}

public void
addPrimaryZone(String zname, String zonefile) throws IOException {
	Name origin = null;
	if (zname != null)
		origin = Name.fromString(zname, Name.root);
	Zone newzone = new Zone(origin, zonefile);
	znames.put(newzone.getOrigin(), newzone);
}

public void
addSecondaryZone(String zone, String remote)
throws IOException, ZoneTransferException
{
	Name zname = Name.fromString(zone, Name.root);
	Zone newzone = new Zone(zname, DClass.IN, remote);
	znames.put(zname, newzone);
}

public void
addTSIG(String algstr, String namestr, String key) throws IOException {
	Name name = Name.fromString(namestr, Name.root);
	TSIGs.put(name, new TSIG(algstr, namestr, key));
}

public Cache
getCache(int dclass) {
	Cache c = (Cache) caches.get(new Integer(dclass));
	if (c == null) {
		c = new Cache(dclass);
		caches.put(new Integer(dclass), c);
	}
	return c;
}

public Zone
findBestZone(Name name) {
	Zone foundzone = null;
	foundzone = (Zone) znames.get(name);
	if (foundzone != null)
		return foundzone;
	int labels = name.labels();
	for (int i = 1; i < labels; i++) {
		Name tname = new Name(name, i);
		foundzone = (Zone) znames.get(tname);
		if (foundzone != null)
			return foundzone;
	}
	return null;
}

public RRset
findExactMatch(Name name, int type, int dclass, boolean glue) {
	Zone zone = findBestZone(name);
	if (zone != null)
		return zone.findExactMatch(name, type);
	else {
		RRset [] rrsets;
		Cache cache = getCache(dclass);
		if (glue)
			rrsets = cache.findAnyRecords(name, type);
		else
			rrsets = cache.findRecords(name, type);
		if (rrsets == null)
			return null;
		else
			return rrsets[0]; /* not quite right */
	}
}

void
addRRset(Name name, Message response, RRset rrset, int section, int flags) {
	for (int s = 1; s <= section; s++)
		if (response.findRRset(name, rrset.getType(), s))
			return;
	if ((flags & FLAG_SIGONLY) == 0) {
		Iterator it = rrset.rrs();
		while (it.hasNext()) {
			Record r = (Record) it.next();
			if (r.getName().isWild() && !name.isWild())
				r = r.withName(name);
			response.addRecord(r, section);
		}
	}
	if ((flags & (FLAG_SIGONLY | FLAG_DNSSECOK)) != 0) {
		Iterator it = rrset.sigs();
		while (it.hasNext()) {
			Record r = (Record) it.next();
			if (r.getName().isWild() && !name.isWild())
				r = r.withName(name);
			response.addRecord(r, section);
		}
	}
}

private final void
addSOA(Message response, Zone zone) {
	response.addRecord(zone.getSOA(), Section.AUTHORITY);
}

private final void
addNS(Message response, Zone zone, int flags) {
	RRset nsRecords = zone.getNS();
	addRRset(nsRecords.getName(), response, nsRecords,
		 Section.AUTHORITY, flags);
}

private final void
addCacheNS(Message response, Cache cache, Name name) {
	SetResponse sr = cache.lookupRecords(name, Type.NS, Credibility.HINT);
	if (!sr.isDelegation())
		return;
	RRset nsRecords = sr.getNS();
	Iterator it = nsRecords.rrs();
	while (it.hasNext()) {
		Record r = (Record) it.next();
		response.addRecord(r, Section.AUTHORITY);
	}
}

private void
addGlue(Message response, Name name, int flags) {
	RRset a = findExactMatch(name, Type.A, DClass.IN, true);
	if (a == null)
		return;
	addRRset(name, response, a, Section.ADDITIONAL, flags);
}

private void
addAdditional2(Message response, int section, int flags) {
	Record [] records = response.getSectionArray(section);
	for (int i = 0; i < records.length; i++) {
		Record r = records[i];
		Name glueName = r.getAdditionalName();
		if (glueName != null)
			addGlue(response, glueName, flags);
	}
}

private final void
addAdditional(Message response, int flags) {
	addAdditional2(response, Section.ANSWER, flags);
	addAdditional2(response, Section.AUTHORITY, flags);
}

byte
addAnswer(Message response, Name name, int type, int dclass,
	  int iterations, int flags)
{
	SetResponse sr;
	byte rcode = Rcode.NOERROR;

	if (iterations > 6)
		return Rcode.NOERROR;

	if (type == Type.SIG || type == Type.RRSIG) {
		type = Type.ANY;
		flags |= FLAG_SIGONLY;
	}

	Zone zone = findBestZone(name);
	if (zone != null)
		sr = zone.findRecords(name, type);
	else {
		Cache cache = getCache(dclass);
		sr = cache.lookupRecords(name, type, Credibility.NORMAL);
	}

	if (sr.isUnknown()) {
		addCacheNS(response, getCache(dclass), name);
	}
	if (sr.isNXDOMAIN()) {
		response.getHeader().setRcode(Rcode.NXDOMAIN);
		if (zone != null) {
			addSOA(response, zone);
			if (iterations == 0)
				response.getHeader().setFlag(Flags.AA);
		}
		rcode = Rcode.NXDOMAIN;
	}
	else if (sr.isNXRRSET()) {
		if (zone != null) {
			addSOA(response, zone);
			if (iterations == 0)
				response.getHeader().setFlag(Flags.AA);
		}
	}
	else if (sr.isDelegation()) {
		RRset nsRecords = sr.getNS();
		addRRset(nsRecords.getName(), response, nsRecords,
			 Section.AUTHORITY, flags);
	}
	else if (sr.isCNAME()) {
		CNAMERecord cname = sr.getCNAME();
		RRset rrset = new RRset(cname);
		addRRset(name, response, rrset, Section.ANSWER, flags);
		if (zone != null && iterations == 0)
			response.getHeader().setFlag(Flags.AA);
		rcode = addAnswer(response, cname.getTarget(),
				  type, dclass, iterations + 1, flags);
	}
	else if (sr.isDNAME()) {
		DNAMERecord dname = sr.getDNAME();
		RRset rrset = new RRset(dname);
		addRRset(name, response, rrset, Section.ANSWER, flags);
		Name newname;
		try {
			newname = name.fromDNAME(dname);
		}
		catch (NameTooLongException e) {
			return Rcode.YXDOMAIN;
		}
		rrset = new RRset(new CNAMERecord(name, dclass, 0, newname));
		addRRset(name, response, rrset, Section.ANSWER, flags);
		if (zone != null && iterations == 0)
			response.getHeader().setFlag(Flags.AA);
		rcode = addAnswer(response, newname, type, dclass,
				  iterations + 1, flags);
	}
	else if (sr.isSuccessful()) {
		RRset [] rrsets = sr.answers();
		for (int i = 0; i < rrsets.length; i++)
			addRRset(name, response, rrsets[i],
				 Section.ANSWER, flags);
		if (zone != null) {
			addNS(response, zone, flags);
			if (iterations == 0)
				response.getHeader().setFlag(Flags.AA);
		}
		else
			addCacheNS(response, getCache(dclass), name);
	}
	return rcode;
}

byte []
doAXFR(Name name, Message query, TSIG tsig, TSIGRecord qtsig, Socket s) {
	Zone zone = (Zone) znames.get(name);
	boolean first = true;
	if (zone == null)
		return errorMessage(query, Rcode.REFUSED);
	Iterator it = zone.AXFR();
	try {
		DataOutputStream dataOut;
		dataOut = new DataOutputStream(s.getOutputStream());
		int id = query.getHeader().getID();
		while (it.hasNext()) {
			RRset rrset = (RRset) it.next();
			Message response = new Message(id);
			Header header = response.getHeader();
			header.setFlag(Flags.QR);
			header.setFlag(Flags.AA);
			addRRset(rrset.getName(), response, rrset,
				 Section.ANSWER, FLAG_DNSSECOK);
			if (tsig != null) {
				tsig.applyStream(response, qtsig, first);
				qtsig = response.getTSIG();
			}
			first = false;
			byte [] out = response.toWire();
			dataOut.writeShort(out.length);
			dataOut.write(out);
		}
	}
	catch (IOException ex) {
		System.out.println("AXFR failed");
	}
	try {
		s.close();
	}
	catch (IOException ex) {
	}
	return null;
}

/*
 * Note: a null return value means that the caller doesn't need to do
 * anything.  Currently this only happens if this is an AXFR request over
 * TCP.
 */
byte []
generateReply(Message query, byte [] in, int length, Socket s)
throws IOException
{
	Header header;
	boolean badversion;
	int maxLength;
	int flags = 0;

	header = query.getHeader();
	if (header.getFlag(Flags.QR))
		return null;
	if (header.getRcode() != Rcode.NOERROR)
		return errorMessage(query, Rcode.FORMERR);
	if (header.getOpcode() != Opcode.QUERY)
		return errorMessage(query, Rcode.NOTIMP);

	Record queryRecord = query.getQuestion();

	TSIGRecord queryTSIG = query.getTSIG();
	TSIG tsig = null;
	if (queryTSIG != null) {
		tsig = (TSIG) TSIGs.get(queryTSIG.getName());
		if (tsig == null ||
		    tsig.verify(query, in, length, null) != Rcode.NOERROR)
			return formerrMessage(in);
	}

	OPTRecord queryOPT = query.getOPT();
	if (queryOPT != null && queryOPT.getVersion() > 0)
		badversion = true;

	if (s != null)
		maxLength = 65535;
	else if (queryOPT != null)
		maxLength = Math.max(queryOPT.getPayloadSize(), 512);
	else
		maxLength = 512;

	if (queryOPT != null && (queryOPT.getFlags() & ExtendedFlags.DO) != 0)
		flags = FLAG_DNSSECOK;

	Message response = new Message(query.getHeader().getID());
	response.getHeader().setFlag(Flags.QR);
	if (query.getHeader().getFlag(Flags.RD))
		response.getHeader().setFlag(Flags.RD);
	response.addRecord(queryRecord, Section.QUESTION);

	Name name = queryRecord.getName();
	int type = queryRecord.getType();
	int dclass = queryRecord.getDClass();
	if (type == Type.AXFR && s != null)
		return doAXFR(name, query, tsig, queryTSIG, s);
	if (!Type.isRR(type) && type != Type.ANY)
		return errorMessage(query, Rcode.NOTIMP);

	byte rcode = addAnswer(response, name, type, dclass, 0, flags);
	if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN)
		return errorMessage(query, rcode);

	addAdditional(response, flags);

	if (queryOPT != null) {
		int optflags = (flags == FLAG_DNSSECOK) ? ExtendedFlags.DO : 0;
		OPTRecord opt = new OPTRecord((short)4096, rcode, (byte)0,
					      optflags);
		response.addRecord(opt, Section.ADDITIONAL);
	}

	response.setTSIG(tsig, Rcode.NOERROR, queryTSIG);
	return response.toWire(maxLength);
}

byte []
buildErrorMessage(Header header, int rcode, Record question) {
	Message response = new Message();
	response.setHeader(header);
	for (int i = 0; i < 4; i++)
		response.removeAllRecords(i);
	if (rcode == Rcode.SERVFAIL)
		response.addRecord(question, Section.QUESTION);
	header.setRcode(rcode);
	return response.toWire();
}

public byte []
formerrMessage(byte [] in) {
	Header header;
	try {
		header = new Header(in);
	}
	catch (IOException e) {
		return null;
	}
	return buildErrorMessage(header, Rcode.FORMERR, null);
}

public byte []
errorMessage(Message query, int rcode) {
	return buildErrorMessage(query.getHeader(), rcode,
				 query.getQuestion());
}

public void
TCPclient(Socket s) {
	try {
		int inLength;
		DataInputStream dataIn;
		DataOutputStream dataOut;
		byte [] in;

		InputStream is = s.getInputStream();
		dataIn = new DataInputStream(is);
		inLength = dataIn.readUnsignedShort();
		in = new byte[inLength];
		dataIn.readFully(in);

		Message query;
		byte [] response = null;
		try {
			query = new Message(in);
			response = generateReply(query, in, in.length, s);
			if (response == null)
				return;
		}
		catch (IOException e) {
			response = formerrMessage(in);
		}
		dataOut = new DataOutputStream(s.getOutputStream());
		dataOut.writeShort(response.length);
		dataOut.write(response);
	}
	catch (IOException e) {
		System.out.println("TCPclient(" +
				   addrport(s.getLocalAddress(),
					    s.getLocalPort()) +
				   "): " + e);
	}
	finally {
		try {
			s.close();
		}
		catch (IOException e) {}
	}
}

public void
serveTCP(InetAddress addr, int port) {
	try {
		ServerSocket sock = new ServerSocket(port, 128, addr);
		while (true) {
			final Socket s = sock.accept();
			Thread t;
			t = new Thread(new Runnable() {
					public void run() {TCPclient(s);}});
			t.start();
		}
	}
	catch (IOException e) {
		System.out.println("serveTCP(" + addrport(addr, port) + "): " +
				   e);
	}
}

public void
serveUDP(InetAddress addr, int port) {
	try {
		DatagramSocket sock = new DatagramSocket(port, addr);
		final short udpLength = 512;
		byte [] in = new byte[udpLength];
		DatagramPacket indp = new DatagramPacket(in, in.length);
		DatagramPacket outdp = null;
		while (true) {
			indp.setLength(in.length);
			try {
				sock.receive(indp);
			}
			catch (InterruptedIOException e) {
				continue;
			}
			Message query;
			byte [] response = null;
			try {
				query = new Message(in);
				response = generateReply(query, in,
							 indp.getLength(),
							 null);
				if (response == null)
					continue;
			}
			catch (IOException e) {
				response = formerrMessage(in);
			}
			if (outdp == null)
				outdp = new DatagramPacket(response,
							   response.length,
							   indp.getAddress(),
							   indp.getPort());
			else {
				outdp.setData(response);
				outdp.setLength(response.length);
				outdp.setAddress(indp.getAddress());
				outdp.setPort(indp.getPort());
			}
			sock.send(outdp);
		}
	}
	catch (IOException e) {
		System.out.println("serveUDP(" + addrport(addr, port) + "): " +
				   e);
	}
}

public void
addTCP(final InetAddress addr, final int port) {
	Thread t;
	t = new Thread(new Runnable() {
			public void run() {serveTCP(addr, port);}});
	t.start();
}

public void
addUDP(final InetAddress addr, final int port) {
	Thread t;
	t = new Thread(new Runnable() {
			public void run() {serveUDP(addr, port);}});
	t.start();
}

public static void main(String [] args) {
	if (args.length > 1) {
		System.out.println("usage: jnamed [conf]");
		System.exit(0);
	}
	jnamed s;
	try {
		String conf;
		if (args.length == 1)
			conf = args[0];
		else
			conf = "jnamed.conf";
		s = new jnamed(conf);
	}
	catch (IOException e) {
		System.out.println(e);
	}
	catch (ZoneTransferException e) {
		System.out.println(e);
	}
}

}
