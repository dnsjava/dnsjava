import java.io.*;

public class dnsRecord {

dnsName rname;
short rtype, rclass, rlength;
int rttl;

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
	switch (type) {
		case dns.A:	return new dnsARecord(name, _class);
		case dns.NS:	return new dnsNSRecord(name, _class);
		case dns.CNAME:	return new dnsCNAMERecord(name, _class);
		case dns.SOA:	return new dnsSOARecord(name, _class);
		case dns.PTR:	return new dnsPTRRecord(name, _class);
		case dns.MX:	return new dnsMXRecord(name, _class);
		case dns.TXT:	return new dnsTXTRecord(name, _class);
		case dns.KEY:	return new dnsKEYRecord(name, _class);
		case dns.SIG:	return new dnsSIGRecord(name, _class);
		case dns.NXT:	return new dnsNXTRecord(name, _class);
		case dns.TSIG:	return new dnsTSIGRecord(name, _class);
		default:	return new dnsRecord(name, type, _class);
	}
}


static dnsRecord buildRecord(CountedDataInputStream in, int section,
			     dnsCompression c) throws IOException
{
	short type, _class;
	dnsName name;
	dnsRecord rec;

	name = new dnsName(in, c);

	type = in.readShort();
	_class = in.readShort();
	rec = newRecord(name, type, _class);

	if (section == dns.QUESTION)
		return rec;

	rec.rttl = in.readInt();
	rec.rlength = in.readShort();
	rec.parse(in, c);
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

void rrToBytes(DataOutputStream out) throws IOException {
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

}
