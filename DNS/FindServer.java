// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;

class FindServer {

static String [] server = null;
static Name [] search = null;
static boolean probed = false;

static void
findProperty() {
	String s;
	s = System.getProperty("dns.resolver");
	if (s != null) {
		server = new String[1];
		server[0] = s;
	}
	else {
		Vector v = null;
		for (int i = 1; i <= 5; i++) {
			s = System.getProperty("dns.server" + i);
			if (s == null)
				break;
			if (v == null)
				v = new Vector();
			v.addElement(s);
		}
		if (v != null) {
			server = new String[v.size()];
			for (int i = 0; i < v.size(); i++)
				server[i] = (String) v.elementAt(i);
		}
	}
	Vector v = null;
	for (int i = 1; i <= 5; i++) {
		s = System.getProperty("dns.search" + i);
		if (s == null)
			break;
		if (v == null)
			v = new Vector();
		v.addElement(s);
	}
	if (v != null) {
		search = new Name[v.size() + 1];
		for (int i = 0; i < v.size(); i++)
			search[i] = new Name((String)v.elementAt(i));
	}
}

static void
findUnix() {
	InputStream in = null;
	try {
		in = new FileInputStream("/etc/resolv.conf");
	}
	catch (FileNotFoundException e) {
		return;
	}
	InputStreamReader isr = new InputStreamReader(in);
	BufferedReader br = new BufferedReader(isr);
	Vector vserver = null;
	Vector vsearch = null;
	try {
		String line;
		while ((line = br.readLine()) != null) {
			if (line.startsWith("nameserver")) {
				if (vserver == null)
					vserver = new Vector();
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip nameserver */
				vserver.addElement(st.nextToken());
			}
			else if (line.startsWith("domain")) {
				if (vsearch == null)
					vsearch = new Vector();
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip domain */
				String s = st.nextToken();
				if (!vsearch.contains(s))
					vsearch.addElement(s);
			}
			else if (line.startsWith("search")) {
				if (vsearch == null)
					vsearch = new Vector();
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip domain */
				String s;
				while (st.hasMoreTokens()) {
					s = st.nextToken();
					if (!vsearch.contains(s))
						vsearch.addElement(s);
				}
			}
		}
	}
	catch (IOException e) {
	}
	if (vserver != null) {
		server = new String[vserver.size()];
		for (int i = 0; i < vserver.size(); i++)
			server[i] = (String) vserver.elementAt(i);
	}
	if (vsearch != null) {
		search = new Name[vsearch.size() + 1];
		for (int i = 0; i < vsearch.size(); i++)
			search[i] = new Name((String)vsearch.elementAt(i));
	}
}

public static void
probe() {
	if (probed)
		return;
	probed = true;
	findProperty();
	if (server != null)
		return;
	findUnix();
	return;
}

public static String []
servers() {
	probe();
	return server;
}

public static String
server() {
	String [] array = servers();
	if (array == null)
		return null;
	else
		return array[0];
}

public static Name []
searchPath() {
	probe();
	if (search == null)
		search = new Name [1];
	search[search.length - 1] = Name.root;
	return search;
}

}
