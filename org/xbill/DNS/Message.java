import java.util.Vector;
import java.io.*;

public class dnsMessage {

private dnsHeader header;
private Vector [] sections;
private int size;

dnsMessage() {
	sections = new Vector[4];
	for (int i=0; i<4; i++)
		sections[i] = new Vector();
	header = new dnsHeader();
}

dnsMessage(CountedDataInputStream in) throws IOException {
	this();
	int startpos = in.pos();
	dnsCompression c = new dnsCompression();
	header = new dnsHeader(in);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < header.getCount(i); j++) {
			dnsRecord rec = dnsRecord.buildRecord(in, i, c);
			sections[i].addElement(rec);
		}
	}
	size = in.pos() - startpos;
}

dnsMessage(byte [] b) throws IOException {
	this(new CountedDataInputStream(new ByteArrayInputStream(b)));
}

void setHeader(dnsHeader h) {
	header = h;
}

dnsHeader getHeader() {
	return header;
}

void addRecord(int section, dnsRecord r) {
	sections[section].addElement(r);
	header.incCount(section);
}

boolean removeRecord(int section, dnsRecord r) {
	if (sections[section].removeElement(r)) {
		header.decCount(section);
		return true;
	}
	else
		return false;
}

dnsTSIGRecord getTSIG() {
	int count = header.getCount(dns.ADDITIONAL);
	if (count == 0)
		return null;
	Vector v = sections[dns.ADDITIONAL];
	dnsRecord rec = (dnsRecord) v.elementAt(count - 1);
	if (!(rec instanceof dnsTSIGRecord))
		return null;
	return (dnsTSIGRecord) rec;
}

Vector getSection(int section) {
	return sections[section];
}

void toBytes(DataOutputStream out) throws IOException {
	header.toBytes(out);
	for (int i=0; i<4; i++) {
		if (sections[i].size() == 0)
			continue;
		for (int j=0; j<sections[i].size(); j++) {
			dnsRecord rec = (dnsRecord)sections[i].elementAt(j);
			rec.toBytes(out, i);
		}
	}
}

byte [] toBytes() throws IOException {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	DataOutputStream dout = new DataOutputStream(out);
	toBytes(dout);
	return out.toByteArray();
}

void toCanonicalBytes(DataOutputStream out) throws IOException {
	header.toBytes(out);
	for (int i=0; i<4; i++) {
		if (sections[i].size() == 0)
			continue;
		for (int j=0; j<sections[j].size(); j++) {
			dnsRecord rec = (dnsRecord)sections[i].elementAt(j);
			rec.toCanonicalBytes(out, i);
		}
	}
}

int getNumBytes() {
	return size;
}

}
