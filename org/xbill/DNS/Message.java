import java.util.Vector;
import java.io.*;

public class dnsMessage {

private dnsHeader header;
private Vector [] sections;

dnsMessage() {
	sections = new Vector[4];
	for (int i=0; i<4; i++)
		sections[i] = new Vector();
	header = new dnsHeader();
}

dnsMessage(CountedDataInputStream in) throws IOException {
	this();
	dnsCompression c = new dnsCompression();
	header = new dnsHeader(in);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < header.getCount(i); j++) {
			dnsRecord rec = dnsRecord.buildRecord(in, i, c);
			sections[i].addElement(rec);
		}
	}
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

Vector getSection(int section) {
	return sections[section];
}

void toBytes(DataOutputStream out) throws IOException {
	header.toBytes(out);
	for (int i=0; i<4; i++) {
		if (sections[i].size() == 0)
			continue;
		for (int j=0; j<sections[j].size(); j++) {
			dnsRecord rec = (dnsRecord)sections[i].elementAt(j);
			rec.toBytes(out, i);
		}
	}
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

}
