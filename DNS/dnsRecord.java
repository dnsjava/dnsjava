import java.io.*;
import java.lang.reflect.*;

public class dnsRecord {

dnsName rname;
short rtype, rclass, rlength;
int rttl;
private short msgLength = 0;

byte [] data;

dnsRecord(dnsName name, short type, short _class) {
	rname = name;
	rtype = type;
	rclass = _class;
}

dnsRecord(dnsName rname, short rtype, short rclass, int rttl, byte [] data) {
	this(rname, rtype, rclass);
	this.rttl = rttl;
	this.data = data;
	this.rlength = (short)data.length;
}

static dnsRecord newRecord(dnsName name, short type, short _class) {
	String s = dns.typeString(type);
	try {
		Class c;
		Constructor m;
		dnsRecord rec;

		c = Class.forName("dns" + s + "Record");
		m = c.getConstructor(new Class [] {dnsName.class,
						   java.lang.Short.TYPE});
		rec = (dnsRecord) m.newInstance(new Object []
						{name, new Short(_class)});
		return rec;
	}
	catch (Exception e) {
		if (!(e instanceof ClassNotFoundException))
			System.out.println(e);
		return new dnsRecord(name, type, _class);
	}
}


static dnsRecord buildRecord(CountedDataInputStream in, int section,
			     dnsCompression c) throws IOException
{
	short type, _class;
	dnsName name;
	dnsRecord rec;

	int startpos = in.pos();
	name = new dnsName(in, c);

	type = in.readShort();
	_class = in.readShort();
	rec = newRecord(name, type, _class);

	if (section == dns.QUESTION)
		return rec;

	rec.rttl = in.readInt();
	rec.rlength = in.readShort();
	rec.parse(in, c);
	rec.msgLength = (short)(in.pos() - startpos);
	return rec;
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	data = new byte[rlength];
	in.read(data);
}

void toBytes(DataOutputStream out, int section) throws IOException {
	rname.toBytes(out);
	out.writeShort(rtype);
	out.writeShort(rclass);
	if (section == dns.QUESTION)
		return;
	out.writeInt(rttl);
	out.writeShort(rlength);
	rrToBytes(out);
}

byte [] toBytes(int section) throws IOException {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	DataOutputStream dout = new DataOutputStream(out);
	toBytes(dout, section);
	return out.toByteArray();
}

void rrToBytes(DataOutputStream out) throws IOException {
	if (rlength > 0)
		out.write(data);
}

void toCanonicalBytes(DataOutputStream out, int section) throws IOException {
	rname.toCanonicalBytes(out);
	out.writeShort(rtype);
	out.writeShort(rclass);
	if (section == dns.QUESTION)
		return;
	out.writeInt(rttl);
	out.writeShort(rlength);
	rrToCanonicalBytes(out);
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	out.write(data);
}

public String toString() {
	String rr;
	StringBuffer sb = new StringBuffer();
	rr = rrToString();
	sb.append(rname);
	sb.append("\t");
	sb.append(rttl);
	sb.append("\t");
	sb.append(dns.typeString(rtype));
	if (rclass != dns.IN) {
		sb.append("\t");
		sb.append(dns.classString(rclass));
	}
	if (rr != null) {
		if (this instanceof dnsSIGRecord)
			sb.append(" ");
		else
			sb.append("\t");
		sb.append(rr);
	}
	return sb.toString();
}

String rrToString() {
	return null;
}

short
rrLength() {
	return msgLength;
}

}
