// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;

public class Zone {

Hashtable data;
Name origin = null;

public Zone(String file) throws IOException {
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

	Record record = null;

	data = new Hashtable();

	while (true) {
		line = IO.readExtendedLine(br);
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
findName(Name name) {
	return (Vector) data.get(name);
}

public Name
getOrigin() {
	return origin;
}

Name
parseOrigin(MyStringTokenizer st) throws IOException {
	return new Name(st.nextToken());
}

Record
parseRR(MyStringTokenizer st, boolean useLast, Record last, Name origin)
throws IOException
{
	Name name;
	int ttl;
	short type, dclass;

	if (!useLast)
		name = new Name(st.nextToken(), origin);
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

	return Record.fromString(name, type, dclass, ttl, st, origin);
}

}
