// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;

class FindResolver {

static String server = null;

static String
findProperty() {
	return System.getProperty("dns.resolver");
}

static String
findUnix() {
	InputStream in = null;
	try {
		in = new FileInputStream("/etc/resolv.conf");
	}
	catch (FileNotFoundException e) {
		return null;
	}
	InputStreamReader isr = new InputStreamReader(in);
	BufferedReader br = new BufferedReader(isr);
	try {
		while (true) {
			String line = br.readLine();
			if (line == null)
				return null;
			if (!line.startsWith("nameserver "))
				continue;
			StringTokenizer st = new StringTokenizer(line);
			st.nextToken(); /* skip nameserver */
			return st.nextToken();
		}
	}
	catch (IOException e) {
	}
	return null;
}

public static String
find() {
	if (server != null)
		return server;

	server = findProperty();
	if (server != null)
		return server;

	server = findUnix();
	if (server != null)
		return server;

	return null;
}

}
