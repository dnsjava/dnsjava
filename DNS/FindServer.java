// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;

class FindServer {

static String [] server = null;
static boolean searched = false;

static String []
findProperty() {
	String s;
	String [] array;
	s = System.getProperty("dns.resolver");
	if (s != null) {
		array = new String[1];
		array[0] = s;
	}
	else {
		Vector v = null;
		for (int i = 1; i <= 3; i++) {
			s = System.getProperty("dns.server" + i);
			if (s == null)
				break;
			if (v == null)
				v = new Vector();
			v.addElement(s);
		}
		if (v == null)
			return null;
		array = new String[v.size()];
		for (int i = 0; i < v.size(); i++)
			array[i] = (String) v.elementAt(i);
	}
	return array;
}

static String []
findUnix() {
	InputStream in = null;
	String [] array;
	try {
		in = new FileInputStream("/etc/resolv.conf");
	}
	catch (FileNotFoundException e) {
		return null;
	}
	InputStreamReader isr = new InputStreamReader(in);
	BufferedReader br = new BufferedReader(isr);
	Vector v = null;
	try {
		while (true) {
			String line = br.readLine();
			if (line == null)
				return null;
			if (!line.startsWith("nameserver "))
				continue;
			if (v == null)
				v = new Vector();
			StringTokenizer st = new StringTokenizer(line);
			st.nextToken(); /* skip nameserver */
			v.addElement(st.nextToken());
		}
	}
	catch (IOException e) {
	}
	if (v == null)
		return null;
	array = new String[v.size()];
	for (int i = 0; i < v.size(); i++)
		array[i] = (String) v.elementAt(i);
	return null;
}

public static String []
find() {
	if (server != null || searched)
		return server;

	searched = true;
	server = findProperty();
	if (server != null)
		return server;

	server = findUnix();
	if (server != null)
		return server;

	return null;
}

public static String
find1() {
	String [] array = find();
	if (array == null)
		return null;
	else
		return array[0];
}

}
