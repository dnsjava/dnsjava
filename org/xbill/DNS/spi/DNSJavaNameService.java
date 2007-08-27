// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.spi;

import java.net.*;
import java.util.*;
import org.xbill.DNS.*;
import sun.net.spi.nameservice.*;

/**
 * This class implements a Name Service Provider, which Java can use 
 * (starting with version 1.4), to perform DNS resolutions instead of using 
 * the standard calls. 
 * <p>
 * This Name Service Provider uses dnsjava.
 * <p>
 * To use this provider, you must set the following system propery:
 * <b>sun.net.spi.nameservice.provider.1=dns,dnsjava</b>
 *
 * @author Brian Wellington
 * @author Paul Cowan (pwc21@yahoo.com)
 */

public class DNSJavaNameService implements NameService {

private static final String nsProperty = "sun.net.spi.nameservice.nameservers";
private static final String domainProperty = "sun.net.spi.nameservice.domain";
private static final String v6Property = "java.net.preferIPv6Addresses";

private boolean preferV6 = false;

/**
 * Creates a DNSJavaNameService instance.
 * <p>
 * Uses the
 * <b>sun.net.spi.nameservice.nameservers</b>,
 * <b>sun.net.spi.nameservice.domain</b>, and
 * <b>java.net.preferIPv6Addresses</b> properties for configuration.
 */
protected DNSJavaNameService() {
	String nameServers = System.getProperty(nsProperty);
	String domain = System.getProperty(domainProperty);
	String v6 = System.getProperty(v6Property);

	if (nameServers != null) {
		StringTokenizer st = new StringTokenizer(nameServers, ",");
		String [] servers = new String[st.countTokens()];
		int n = 0;
		while (st.hasMoreTokens())
			servers[n++] = st.nextToken();
		try {
			Resolver res = new ExtendedResolver(servers);
			Lookup.setDefaultResolver(res);
		}
		catch (UnknownHostException e) {
			System.err.println("DNSJavaNameService: invalid " +
					   nsProperty);
		}
	}

	if (domain != null) {
		try {
			Lookup.setDefaultSearchPath(new String[] {domain});
		}
		catch (TextParseException e) {
			System.err.println("DNSJavaNameService: invalid " +
					   domainProperty);
		}
	}

	if (v6 != null && v6.equalsIgnoreCase("true"))
		preferV6 = true;
}

/**
 * Performs a forward DNS lookup for the host name.
 * @param host The host name to resolve.
 * @return All the ip addresses found for the host name.
 */
public InetAddress []
lookupAllHostAddr(String host) throws UnknownHostException {
	Name name = null;

	try {
		name = new Name(host);
	}
	catch (TextParseException e) {
		throw new UnknownHostException(host);
	}

	Record [] records = null;
	if (preferV6)
		records = new Lookup(name, Type.AAAA).run();
	if (records == null)
		records = new Lookup(name, Type.A).run();
	if (records == null && !preferV6)
		records = new Lookup(name, Type.AAAA).run();
	if (records == null)
		throw new UnknownHostException(host);

	InetAddress[] array = new InetAddress[records.length];
	for (int i = 0; i < records.length; i++) {
		Record record = records[i];
		if (records[i] instanceof ARecord) {
			ARecord a = (ARecord) records[i];
			array[i] = a.getAddress();
		} else {
			AAAARecord aaaa = (AAAARecord) records[i];
			array[i] = aaaa.getAddress();
		}
	}
	return array;
}

/**
 * Performs a reverse DNS lookup.
 * @param addr The ip address to lookup.
 * @return The host name found for the ip address.
 */
public String getHostByAddr(byte [] addr) throws UnknownHostException {
	Name name = ReverseMap.fromAddress(InetAddress.getByAddress(addr));
	Record [] records = new Lookup(name, Type.PTR).run();
	if (records == null)
		throw new UnknownHostException();
	return ((PTRRecord) records[0]).getTarget().toString();
}

}
