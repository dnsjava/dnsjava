// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;

/**
 * A helper class that tries to locate name servers and the search path to
 * be appended to unqualified names.  Currently, this works if either the
 * appropriate properties are set, the OS has a unix-like /etc/resolv.conf,
 * or the system is Windows based with ipconfig or winipcfg.  There is no
 * reason for these routines to be called directly except curiosity.
 *
 * @author Brian Wellington
 */

public class FindServer {

private static String [] server = null;
private static Name [] search = null;
private static boolean probed = false;

private
FindServer() {}

/**
 * Looks in the system properties to find servers and a search path.
 * Servers are defined by dns.server=server1,server2...
 * The search path is defined by dns.search=domain1,domain2...
 */
private static void
findProperty() {
	String s, prop;
	List l = new ArrayList(0);
	StringTokenizer st;

	prop = System.getProperty("dns.server");
	if (prop != null) {
		st = new StringTokenizer(prop, ",");
		while (st.hasMoreTokens()) {
			s = st.nextToken();
			l.add(s);
		}
		if (l.size() > 0)
			server = (String []) l.toArray(new String[l.size()]);
	}

	l.clear();
	prop = System.getProperty("dns.search");
	if (prop != null) {
		st = new StringTokenizer(prop, ",");
		while (st.hasMoreTokens()) {
			s = st.nextToken();
			try {
				l.add(Name.fromString(s, Name.root));
			}
			catch (TextParseException e) {}
		}
		if (l.size() > 0)
			search = (Name []) l.toArray(new Name[l.size()]);
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
	List lserver = new ArrayList(0);
	List lsearch = new ArrayList(0);
	try {
		String line;
		while ((line = br.readLine()) != null) {
			if (line.startsWith("nameserver")) {
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip nameserver */
				lserver.add(st.nextToken());
			}
			else if (line.startsWith("domain")) {
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip domain */
				if (!st.hasMoreTokens())
					continue;
				String s = st.nextToken();
				if (!lsearch.contains(s))
					lsearch.add(s);
			}
			else if (line.startsWith("search")) {
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip search */
				String s;
				while (st.hasMoreTokens()) {
					s = st.nextToken();
					if (!lsearch.contains(s))
						lsearch.add(s);
				}
			}
		}
		br.close();
	}
	catch (IOException e) {
	}

	if (server == null && lserver.size() > 0)
		server = (String [])lserver.toArray(new String[lserver.size()]);

	if (search == null && lsearch.size() > 0) {
		List l = new ArrayList();
		for (int i = 0; i < lsearch.size(); i++) {
			String s = (String)lsearch.get(i);
			try {
				l.add(Name.fromString(s, Name.root));
			}
			catch (TextParseException e) {
			}
		}
		search = (Name [])l.toArray(new Name[l.size()]);
	}
}

/**
 * Parses the output of winipcfg or ipconfig.
 */
private static void
findWin(InputStream in) {
	BufferedReader br = new BufferedReader(new InputStreamReader(in));
	try {
		List lserver = new ArrayList();
		String line = null;
		boolean readingServers = false;
		while ((line = br.readLine()) != null) {
			StringTokenizer st = new StringTokenizer(line);
			if (!st.hasMoreTokens()) {
				readingServers = false;
				continue;
			}
			String s = st.nextToken();
			if (line.indexOf(":") != -1)
				readingServers = false;
			
			if (line.indexOf("Host Name") != -1) {
				while (st.hasMoreTokens())
					s = st.nextToken();
				Name name;
				try {
					name = Name.fromString(s, null);
				}
				catch (TextParseException e) {
					continue;
				}
				if (name.labels() == 1)
					continue;
				name = new Name(name, 1);
				search = new Name[1];
				search[0] = name;
			}
			else if (readingServers ||
				 line.indexOf("DNS Servers") != -1)
			{
				while (st.hasMoreTokens())
					s = st.nextToken();
				if (s.equals(":"))
					continue;
				lserver.add(s);
				readingServers = true;
			}
		}
		
		if (server == null && lserver.size() > 0)
			server = (String [])lserver.toArray
						(new String[lserver.size()]);
	}
	catch (IOException e) {
	}
	finally {
		try {
			br.close();
		}
		catch (IOException e) {
		}
	}
	return;
}

/**
 * Calls winipcfg and parses the result to find servers and a search path.
 */
private static void
find95() {
	String s = "winipcfg.out";
	try {
		Process p;
		p = Runtime.getRuntime().exec("winipcfg /all /batch " + s);
		p.waitFor();
		File f = new File(s);
		findWin(new FileInputStream(f));
		new File(s).delete();
	}
	catch(Exception e) {
		return;
	}
}

/**
 * Calls ipconfig and parses the result to find servers and a search path.
 */
private static void
findNT() {
	try {
		Process p;
		p = Runtime.getRuntime().exec("ipconfig /all");
		findWin(p.getInputStream());
		p.destroy();
	}
	catch(Exception e) {
		return;
	}
}

synchronized private static void
probe() {
	if (probed)
		return;
	probed = true;
	findProperty();
	if (server == null || search == null) {
		String OS = System.getProperty("os.name");
		if (OS.indexOf("Windows") != -1) {
			if (OS.indexOf("NT") != -1 ||
			    OS.indexOf("2000") != -1 ||
			    OS.indexOf("XP") != -1)
				findNT();
			else
				find95();
		}
		else
			findUnix();
	}
	if (search == null)
		search = new Name[1];
	else {
		Name [] oldsearch = search;
		search = new Name[oldsearch.length + 1];
		System.arraycopy(oldsearch, 0, search, 0, oldsearch.length);
	}
	search[search.length - 1] = Name.root;
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
