import java.lang.reflect.*;
import java.io.*;
import java.net.*;
import java.util.*;
import DNS.*;

public class jnamed {

Zone [] zones;
int zcount;
Hashtable znames;

public
jnamed() {
	zones = new Zone[20];
	zcount = 0;
	znames = new Hashtable();
};

public void
addZone(String zonefile, int type) throws IOException {
	Zone newzone = new Zone(zonefile, type, zones[0]);
	znames.put(newzone.getOrigin(), newzone);
/*System.out.println("Adding zone named <" + newzone.getOrigin() + ">");*/
	zones[zcount++] = newzone;
};

public Zone
findBestZone(Name name) {
	Zone foundzone = null;
	Name tname = name;
	do {
/*System.out.println("Looking for zone named <" + tname + ">");*/
		foundzone = (Zone) znames.get(tname);
		if (foundzone != null)
			return foundzone;
		tname = new Name(tname, 1);
	} while (!tname.equals(Name.root));
	return null;
}

public RRset
findExactMatch(Name name, short type, short dclass) {
	Zone zone = findBestZone(name);
	Hashtable sets = zone.findName(name);
	if (sets == null)
		return null;
	Short Type = new Short(type);
	RRset rrset = (RRset) sets.get(Type);
	return rrset;
	
}

void
addRRset(Message response, RRset rrset) {
	Enumeration e = rrset.rrs();
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		response.addRecord(Section.ANSWER, r);
	}
}


void
addAuthority(Message response, Zone zone) {
	if (response.getHeader().getCount(Section.ANSWER) > 0) {
		RRset nsRecords = (RRset) zone.getNS();
		Enumeration e = nsRecords.rrs();
		while (e.hasMoreElements()) {
			Record r = (Record) e.nextElement();
			if (response.findRecord(Section.ANSWER, r) == false)
				response.addRecord(Section.AUTHORITY, r);
		}
	}
	else {
		SOARecord soa = (SOARecord) zone.getSOA();
		response.addRecord(Section.AUTHORITY, soa);
	}
}

private void
addGlue(Message response, Name name) {
	RRset a = findExactMatch(name, Type.A, DClass.IN);
	Enumeration e = a.rrs();
	while (e.hasMoreElements()) {
			Record r = (Record) e.nextElement();
			if (response.findRecord(r) == false)
				response.addRecord(Section.ADDITIONAL, r);
	}
}

private void
addAdditional2(Message response, int section) {
	Enumeration e = response.getSection(section);
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		try {
			Method m = r.getClass().getMethod("getTarget", null);
			Name glueName = (Name) m.invoke(r, null);
			addGlue(response, glueName);
		}
		catch (Exception ex) {
		}
	}
	
}

void
addAdditional(Message response) {
	addAdditional2(response, Section.ANSWER);
	addAdditional2(response, Section.AUTHORITY);
}

Message
generateReply(Message query) {
	Enumeration qds = query.getSection(Section.QUESTION);
	Record queryRecord = (Record) qds.nextElement();

	Message response = new Message();
	response.getHeader().setID(query.getHeader().getID());
	response.getHeader().setFlag(Flags.AA);
	response.getHeader().setFlag(Flags.QR);
	response.addRecord(Section.QUESTION, queryRecord);

	Name name = queryRecord.getName();
	short type = queryRecord.getType();
	Zone zone = findBestZone(name);
	if (zone == null) {
		response.getHeader().setRcode(Rcode.SERVFAIL);
	}
	else {
/*System.out.println("Looking up name <" + name + "> in [" + zone.getOrigin() + "]");*/
		Hashtable nameRecords = (Hashtable) zone.findName(name);
		if (nameRecords == null) {
			response.getHeader().setRcode(Rcode.NXDOMAIN);
		}
		else {
			if (type == Type.ANY) {
				Enumeration e = nameRecords.elements();
				while (e.hasMoreElements()) {
					RRset rrset = (RRset) e.nextElement();
					addRRset(response, rrset);
				}
			}
			else {
				Short Type = new Short(type);
				RRset rrset = (RRset) nameRecords.get(Type);
				if (rrset != null)
					addRRset(response, rrset);
			}
		}
		addAuthority(response, zone);
		addAdditional(response);
	}
	return response;
}

public int
truncateSection(Message in, int maxLength, int length, int section) {
	int removed = 0;
	Record [] records = in.getSectionArray(section);
	for (int i = records.length - 1; i >= 0; i--) {
		Record r = records[i];
		removed += r.getWireLength();
		length -= r.getWireLength();
		in.removeRecord(section, r);
		if (length > maxLength)
			continue;
		else {
			for (int j = i - 1; j >= 0; j--) {
				Record r2 = records[j];
				if (!r.getName().equals(r2.getName()) ||
				    r.getType() != r2.getType() ||
				    r.getDClass() != r2.getDClass())
					break;
				removed += r2.getWireLength();
				length -= r2.getWireLength();
				in.removeRecord(section, r2);
			}
			return removed;
		}
	}
	return removed;
}

public void
truncate(Message in, int length, int maxLength) {
	length -= truncateSection(in, maxLength, length, Section.ADDITIONAL);
	if (length < maxLength)
		return;
	in.getHeader().setFlag(Flags.TC);
	length -= truncateSection(in, maxLength, length, Section.AUTHORITY);
	if (length < maxLength)
		return;
	length -= truncateSection(in, maxLength, length, Section.ANSWER);
}

public void
serveTCP(short port) {
	try {
		ServerSocket sock = new ServerSocket(port);
		while (true) {
			Socket s = sock.accept();
			int inLength;
			DataInputStream dataIn;
			DataOutputStream dataOut;
			byte [] in;

			try {
				InputStream is = s.getInputStream();
				dataIn = new DataInputStream(is);
				inLength = dataIn.readUnsignedShort();
				in = new byte[inLength];
				dataIn.readFully(in);
			}
			catch (InterruptedIOException e) {
				s.close();
				continue;
			}
			Message query = new Message(in);
			Message response = generateReply(query);
			byte [] out = response.toWire();
			dataOut = new DataOutputStream(s.getOutputStream());
			dataOut.writeShort(out.length);
			dataOut.write(out);
			s.close();
		}
	}
	catch (IOException e) {
		System.out.println("serveTCP: " + e);
	}
}

public void
serveUDP(short port) {
	try {
		DatagramSocket sock = new DatagramSocket(port);
		while (true) {
			DatagramPacket dp = new DatagramPacket(new byte[512],
							       512);
			try {
				sock.receive(dp);
			}
			catch (InterruptedIOException e) {
				continue;
			}
			byte [] in = new byte[dp.getLength()];
			System.arraycopy(dp.getData(), 0, in, 0, in.length);
			Message query = new Message(in);
			Message response = generateReply(query);
			byte [] out = response.toWire();
			if (out.length > 512) {
				truncate(response, out.length, 512);
				out = response.toWire();
			}
			dp = new DatagramPacket(out, out.length,
						dp.getAddress(), dp.getPort());
			sock.send(dp);
		}
	}
	catch (IOException e) {
		System.out.println("serveUDP: " + e);
	}
}

public void
addTCP(final short port) {
	Thread t;
	t = new Thread(new Runnable() {public void run() {serveUDP(port);}});
	t.start();
}

public void
addUDP(final short port) {
	Thread t;
	t = new Thread(new Runnable() {public void run() {serveTCP(port);}});
	t.start();
}

public static void main(String [] args) {
	if (args.length == 0) {
		System.out.println("usage: server cache zone ... ");
		System.exit(0);	
	}
	jnamed s;
	try {
		s = new jnamed();
		s.addZone(args[0], Zone.CACHE);
		for (int i = 1; i < args.length; i++)
			s.addZone(args[i], Zone.PRIMARY);
		s.addUDP((short)12345);
		s.addTCP((short)12345);
	}
	catch (IOException e) {
		System.out.println(e);
	}
}

}
