// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;

/**
 * A helper class that tries to locate name servers and the search path to
 * be appended to unqualified names.  Currently, this works if either the
 * appropriate properties are set, or the OS has a unix-like /etc/resolv.conf.
 * There is no reason for these routines to be called directly except
 * curiosity.
 */
public class FindServer {

private static String [] server = null;
private static Name [] search = null;
private static boolean probed = false;

private
FindServer() {}

/**
 * Looks in the system properties to find servers and a search path.
 * Properties of the form dns.server1, dns.server2, etc. define servers.
 * Properties of the form dns.search1, dns.seearch, etc. define the search path.
 */
private static void
findProperty() {
	String s;
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

	v = null;
	for (int i = 1; i <= 5; i++) {
		s = System.getProperty("dns.search" + i);
		if (s == null)
			break;
		if (v == null)
			v = new Vector();
		v.addElement(s);
	}
	if (v != null) {
		search = new Name[v.size()];
		for (int i = 0; i < v.size(); i++)
			search[i] = new Name((String)v.elementAt(i));
	}
}

/**
 * Looks in /etc/resolv.conf to find servers and a search path.
 * "nameserver" lines specify servers.  "domain" and "search" lines
 * define the search path.
 */
private static void
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
	if (server == null && vserver != null) {
		server = new String[vserver.size()];
		for (int i = 0; i < vserver.size(); i++)
			server[i] = (String) vserver.elementAt(i);
	}
	if (search == null && vsearch != null) {
		search = new Name[vsearch.size()];
		for (int i = 0; i < vsearch.size(); i++)
			search[i] = new Name((String)vsearch.elementAt(i));
	}
}

private static void
probe() {
	if (probed)
		return;
	probed = true;
	findProperty();
	if (server != null && search != null)
		return;
	findUnix();
	return;
}

/** Returns all located servers */
public static String []
servers() {
	probe();
	return server;
}

/** Returns the first located server */
public static String
server() {
	String [] array = servers();
	if (array == null)
		return null;
	else
		return array[0];
}

/** Returns all entries in the located search path */
public static Name []
searchPath() {
	probe();
	return search;
}

}
