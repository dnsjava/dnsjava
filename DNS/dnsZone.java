import java.util.*;
import java.io.*;

public class dnsZone {

Hashtable data;
dnsName origin = null;

public dnsZone(String file) throws IOException {
	FileInputStream fis;
	try {
		fis = new FileInputStream(file);
	}
	catch (FileNotFoundException e) {
		throw new IOException(e.toString());
	}
	BufferedReader br = new BufferedReader(new InputStreamReader(fis));
	String line;
	MyStringTokenizer st;

	dnsRecord record = null;

	data = new Hashtable();

	while (true) {
		line = dnsIO.readExtendedLine(br);
		if (line == null)
			break;
		boolean space = line.startsWith(" ") || line.startsWith("\t");
			
		st = new MyStringTokenizer(line);

		String s = st.nextToken();
		if (s.equals("$ORIGIN")) {
			origin = parseOrigin(st);
			continue;
		}
		st.putBackToken(s);
		record = parseRR(st, space, record, origin);
		Vector v = (Vector) data.get(record.name);
		if (v == null)
			v = new Vector();
		v.addElement(record);
		data.put(record.name, v);
	}
}

public Vector
findName(dnsName name) {
	return (Vector) data.get(name);
}

public dnsName
getOrigin() {
	return origin;
}

dnsName
parseOrigin(MyStringTokenizer st) throws IOException {
	return new dnsName(st.nextToken());
}

dnsRecord
parseRR(MyStringTokenizer st, boolean useLast, dnsRecord last, dnsName origin)
throws IOException
{
	dnsName name;
	int ttl;
	short type, dclass;

	if (!useLast)
		name = new dnsName(st.nextToken(), origin);
	else
		name = last.name;

	String s = st.nextToken();

	try {
		ttl = Integer.parseInt(s);
		s = st.nextToken();
	}
	catch (NumberFormatException e) {
		if (!useLast || last == null)
			ttl = 3600;
		else
			ttl = last.ttl;
	}

	if ((dclass = dns.classValue(s)) > 0)
		s = st.nextToken();
	else
		dclass = dns.IN;
		

	if ((type = dns.typeValue(s)) < 0)
		throw new IOException("Parse error");

	return dnsRecord.fromString(name, type, dclass, ttl, st, origin);
}

}
