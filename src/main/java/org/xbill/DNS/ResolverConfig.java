// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.lang.reflect.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Stream;

/**
 * A class that tries to locate name servers and the search path to
 * be appended to unqualified names.
 *
 * The following are attempted, in order, until one succeeds.
 * <UL>
 *   <LI>The properties 'dns.server' and 'dns.search' (comma delimited lists)
 *       are checked.  The servers can either be IP addresses or hostnames
 *       (which are resolved using Java's built in DNS support).
 *   <LI>The sun.net.dns.ResolverConfiguration class is queried.
 *   <LI>On Unix, /etc/resolv.conf is parsed.
 *   <LI>On Windows, ipconfig is called and its output parsed.  This
 *       may fail for non-English versions on Windows.
 *   <LI>"localhost" is used as the nameserver, and the search path is empty.
 * </UL>
 *
 * These routines will be called internally when creating Resolvers/Lookups
 * without explicitly specifying server names, and can also be called
 * directly if desired.
 *
 * @author Brian Wellington
 * @author <a href="mailto:yannick@meudal.net">Yannick Meudal</a>
 * @author <a href="mailto:arnt@gulbrandsen.priv.no">Arnt Gulbrandsen</a>
 */
public class ResolverConfig {

public static final String DNS_SERVER_PROP = "dns.server";
public static final String DNS_SEARCH_PROP = "dns.search";

private String [] servers = null;
private Name [] searchlist = null;
private int ndots = -1;

private static ResolverConfig currentConfig;

static {
	refresh();
}

public
ResolverConfig() {
	if (findProperty())
		return;
	if (findSunJVM())
		return;
	if (servers == null || searchlist == null) {
		String OS = System.getProperty("os.name");
		String vendor = System.getProperty("java.vendor");
		if (OS.contains("Windows")) {
			findWin();
		} else if (OS.contains("NetWare")) {
			findNetware();
		} else if (vendor.contains("Android")) {
			findAndroid();
		} else {
			findUnix();
		}
	}
}

private void
addServer(String server, List<String> list) {
	if (list.contains(server))
		return;
	if (Options.check("verbose"))
		System.out.println("adding server " + server);
	list.add(server);
}

private void
addSearch(String search, List<Name> list) {
	Name name;
	if (Options.check("verbose"))
		System.out.println("adding search " + search);
	try {
		name = Name.fromString(search, Name.root);
	}
	catch (TextParseException e) {
		return;
	}
	if (list.contains(name))
		return;
	list.add(name);
}

private int
parseNdots(String token) {
	token = token.substring(6);
	try {
		int ndots = Integer.parseInt(token);
		if (ndots >= 0) {
			if (Options.check("verbose"))
				System.out.println("setting ndots " + token);
			return ndots;
		}
	}
	catch (NumberFormatException e) {
	}
	return -1;
}

private void
configureFromLists(List<String> lserver, List<Name> lsearch) {
	if (servers == null && lserver.size() > 0)
		servers = lserver.toArray(new String[0]);
	if (searchlist == null && lsearch.size() > 0)
		searchlist = lsearch.toArray(new Name[0]);
}

private void
configureNdots(int lndots) {
	if (ndots < 0 && lndots > 0)
		ndots = lndots;
}

/**
 * Looks in the system properties to find servers and a search path.
 * Servers are defined by dns.server=server1,server2...
 * The search path is defined by dns.search=domain1,domain2...
 */
boolean
findProperty() {
	String prop;
	List<String> lserver = new ArrayList<>(0);
	List<Name> lsearch = new ArrayList<>(0);
	StringTokenizer st;

	prop = System.getProperty(DNS_SERVER_PROP);
	if (prop != null) {
		st = new StringTokenizer(prop, ",");
		while (st.hasMoreTokens())
			addServer(st.nextToken(), lserver);
	}

	prop = System.getProperty(DNS_SEARCH_PROP);
	if (prop != null) {
		st = new StringTokenizer(prop, ",");
		while (st.hasMoreTokens())
			addSearch(st.nextToken(), lsearch);
	}
	configureFromLists(lserver, lsearch);
	return (servers != null && searchlist != null);
}

/**
 * Uses the undocumented Sun DNS implementation to determine the configuration.
 * This doesn't work or even compile with all JVMs (gcj, for example).
 */
private boolean
findSunJVM() {
	List<String> lserver = new ArrayList<>(0);
	List<String> lserver_tmp;
	List<Name> lsearch = new ArrayList<>(0);
	List<String> lsearch_tmp;

	try {
		Class [] noClasses = new Class[0];
		Object [] noObjects = new Object[0];
		String resConfName = "sun.net.dns.ResolverConfiguration";
		Class<?> resConfClass = Class.forName(resConfName);
		Object resConf;

		// ResolverConfiguration resConf = ResolverConfiguration.open();
		Method open = resConfClass.getDeclaredMethod("open", noClasses);
		resConf = open.invoke(null, noObjects);

		// lserver_tmp = resConf.nameservers();
		Method nameservers = resConfClass.getMethod("nameservers",
							    noClasses);
		lserver_tmp = (List<String>) nameservers.invoke(resConf, noObjects);

		// lsearch_tmp = resConf.searchlist();
		Method searchlist = resConfClass.getMethod("searchlist",
							    noClasses);
		lsearch_tmp = (List<String>) searchlist.invoke(resConf, noObjects);
	}
	catch (Exception e) {
		return false;
	}

	if (lserver_tmp.size() == 0)
		return false;
	else {
		for (String s : lserver_tmp)
			addServer(s, lserver);
	}

	if (lsearch_tmp.size() > 0) {
		for (String s : lsearch_tmp)
			addSearch(s, lsearch);
	}
	configureFromLists(lserver, lsearch);
	return true;
}

/**
 * Looks in /etc/resolv.conf to find servers and a search path.
 * "nameserver" lines specify servers.  "domain" and "search" lines
 * define the search path.
 */
boolean
findResolvConf(InputStream in) {
	List<String> lserver = new ArrayList<>(0);
	List<Name> lsearch = new ArrayList<>(0);
	int lndots = -1;
	try (InputStreamReader isr = new InputStreamReader(in);
	     BufferedReader br = new BufferedReader(isr)){
		String line;
		while ((line = br.readLine()) != null) {
			if (line.startsWith("nameserver")) {
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip nameserver */
				addServer(st.nextToken(), lserver);
			}
			else if (line.startsWith("domain")) {
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip domain */
				if (!st.hasMoreTokens())
					continue;
				if (lsearch.isEmpty())
					addSearch(st.nextToken(), lsearch);
			}
			else if (line.startsWith("search")) {
				if (!lsearch.isEmpty())
					lsearch.clear();
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip search */
				while (st.hasMoreTokens())
					addSearch(st.nextToken(), lsearch);
			}
			else if(line.startsWith("options")) {
				StringTokenizer st = new StringTokenizer(line);
				st.nextToken(); /* skip options */
				while (st.hasMoreTokens()) {
					String token = st.nextToken();
					if (token.startsWith("ndots:")) {
						lndots = parseNdots(token);
					}
				}
			}
		}
	}
	catch (IOException e) {
		return false;
	}

	if (lserver.isEmpty()) {
		return false;
	}

	configureFromLists(lserver, lsearch);
	configureNdots(lndots);
	return true;
}

boolean
findUnix() {
	try (InputStream in = Files.newInputStream(Paths.get("/etc/resolv.conf"))) {
		return findResolvConf(in);
	}
	catch (Exception e) {
		return false;
	}
}

boolean
findNetware() {
	try (InputStream in = Files.newInputStream(Paths.get("sys:/etc/resolv.cfg"))) {
		return findResolvConf(in);
	}
	catch (Exception e) {
		return false;
	}
}

/**
 * Parses the output of ipconfig.
 */
boolean
findWin(InputStream in, Locale locale) {
	String packageName = ResolverConfig.class.getPackage().getName();
	String resPackageName = packageName + ".windows.DNSServer";
	ResourceBundle res;
	if (locale != null)
		res = ResourceBundle.getBundle(resPackageName, locale);
	else
		res = ResourceBundle.getBundle(resPackageName);

	String host_name = res.getString("host_name");
	String primary_dns_suffix = res.getString("primary_dns_suffix");
	String dns_suffix = res.getString("dns_suffix");
	String dns_servers = res.getString("dns_servers");

	BufferedReader br = new BufferedReader(new InputStreamReader(in));
	try {
		List<String> lserver = new ArrayList<>();
		List<Name> lsearch = new ArrayList<>();
		String line;
		boolean readingServers = false;
		boolean readingSearches = false;
		while ((line = br.readLine()) != null) {
			StringTokenizer st = new StringTokenizer(line);
			if (!st.hasMoreTokens()) {
				readingServers = false;
				readingSearches = false;
				continue;
			}
			String s = st.nextToken();
			if (line.contains(":")) {
				readingServers = false;
				readingSearches = false;
			}
			
			if (line.contains(host_name)) {
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
				addSearch(s, lsearch);
			} else if (line.contains(primary_dns_suffix)) {
				while (st.hasMoreTokens())
					s = st.nextToken();
				if (s.equals(":"))
					continue;
				addSearch(s, lsearch);
				readingSearches = true;
			} else if (readingSearches ||
				line.contains(dns_suffix))
			{
				while (st.hasMoreTokens())
					s = st.nextToken();
				if (s.equals(":"))
					continue;
				addSearch(s, lsearch);
				readingSearches = true;
			} else if (readingServers ||
				line.contains(dns_servers))
			{
				while (st.hasMoreTokens())
					s = st.nextToken();
				if (s.equals(":"))
					continue;
				addServer(s, lserver);
				readingServers = true;
			}
		}
		if (lserver.isEmpty()) {
			return false;
		}
		configureFromLists(lserver, lsearch);
		return true;
	}
	catch (IOException e) {
		return false;
	}
}

private boolean
findWin(InputStream in) {
	boolean found;
	String property = "org.xbill.DNS.windows.parse.buffer";
	final int defaultBufSize = 8 * 1024;
	int bufSize = Integer.getInteger(property, defaultBufSize);
	BufferedInputStream b = new BufferedInputStream(in, bufSize);
	b.mark(bufSize);
	found = findWin(b, null);
	if (servers == null) {
		try {
			b.reset();
		} 
		catch (IOException e) {
			return false;
		}
		found = findWin(b, new Locale("", ""));
	}
	return found;
}

/**
 * Calls ipconfig and parses the result to find servers and a search path.
 */
boolean
findWin() {
	boolean found;
	try {
		Process p;
		p = Runtime.getRuntime().exec("ipconfig /all");
		found = findWin(p.getInputStream());
		p.destroy();
	}
	catch (Exception e) {
		return false;
	}
	return found;
}

/**
 * Parses the output of getprop, which is the only way to get DNS
 * info on Android. getprop might disappear in future releases, so
 * this code comes with a use-by date.
 */
boolean
findAndroid() {
	// This originally looked for all lines containing .dns; but
	// http://code.google.com/p/android/issues/detail?id=2207#c73
	// indicates that net.dns* should always be the active nameservers, so
	// we use those.
	final String re1 = "^\\d+(\\.\\d+){3}$";
	final String re2 = "^[0-9a-f]+(:[0-9a-f]*)+:[0-9a-f]+$";
	ArrayList<String> lserver = new ArrayList<>();
	ArrayList<Name> lsearch = new ArrayList<>();
	try {
		Class<?> SystemProperties =
		    Class.forName("android.os.SystemProperties");
		Method method =
		    SystemProperties.getMethod("get", String.class);
		final String [] netdns = new String [] {"net.dns1", "net.dns2",
						        "net.dns3", "net.dns4"};
		for (String netdn : netdns) {
			Object[] args = new Object[]{netdn};
			String v = (String) method.invoke(null, args);
			if (v != null &&
				(v.matches(re1) || v.matches(re2)) &&
				!lserver.contains(v))
				lserver.add(v);
		}
	} catch (Exception e) {
		return false;
	}
	if (lserver.isEmpty()) {
		return false;
	}
	configureFromLists(lserver, lsearch);
	return true;
}

/** Returns all located servers */
public String []
servers() {
	return servers;
}

/** Returns the first located server */
public String
server() {
	if (servers == null)
		return null;
	return servers[0];
}

/** Returns all entries in the located search path */
public Name []
searchPath() {
	return searchlist;
}

/**
 * Returns the located ndots value, or the default (1) if not configured.
 * Note that ndots can only be configured in a resolv.conf file, and will only
 * take effect if ResolverConfig uses resolv.conf directly (that is, if the
 * JVM does not include the sun.net.dns.ResolverConfiguration class).
 */
public int
ndots() {
	if (ndots < 0)
		return 1;
	return ndots;
}

/** Gets the current configuration */
public static synchronized ResolverConfig
getCurrentConfig() {
	return currentConfig;
}

/** Gets the current configuration */
public static void
refresh() {
	ResolverConfig newConfig = new ResolverConfig();
	synchronized (ResolverConfig.class) {
		currentConfig = newConfig;
	}
}

}
