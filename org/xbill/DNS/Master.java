// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;

public class Master {

private Name origin = null;
private BufferedReader br;
private Record last = null;

public
Master(String file) throws IOException {
	FileInputStream fis;
	try {
		fis = new FileInputStream(file);
	}
	catch (FileNotFoundException e) {
		throw new IOException(e.toString());
	}
	br = new BufferedReader(new InputStreamReader(fis));
}

public Record
nextRecord() throws IOException {
	String line;
	MyStringTokenizer st;

	while (true) {
		line = IO.readExtendedLine(br);
		if (line == null)
			return null;
		if (line.length() == 0 || line.startsWith(";"))
			continue;

		boolean space = line.startsWith(" ") || line.startsWith("\t");
		st = new MyStringTokenizer(line);

		String s = st.nextToken();
		if (s.equals("$ORIGIN")) {
			origin = parseOrigin(st);
			continue;
		}
		st.putBackToken(s);
		return (last = parseRR(st, space, last, origin));
	}
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
		name = last.getName();

	String s = st.nextToken();

	try {
		ttl = TTL.parseTTL(s);
		s = st.nextToken();
	}
	catch (NumberFormatException e) {
		if (!useLast || last == null)
			ttl = 3600;
		else
			ttl = last.getTTL();
	}

	if ((dclass = DClass.value(s)) > 0)
		s = st.nextToken();
	else
		dclass = DClass.IN;
		

	if ((type = Type.value(s)) < 0)
		throw new IOException("Parse error");

	return Record.fromString(name, type, dclass, ttl, st, origin);
}

}
