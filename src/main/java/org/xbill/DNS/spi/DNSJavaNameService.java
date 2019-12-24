// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.spi;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.StringTokenizer;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import sun.net.spi.nameservice.NameService;

/**
 * This class implements a Name Service Provider, which Java can use (starting with version 1.4), to
 * perform DNS resolutions instead of using the standard calls.
 *
 * <p>This Name Service Provider uses dnsjava.
 *
 * <p>To use this provider, you must set the following system property:
 * <b>sun.net.spi.nameservice.provider.1=dns,dnsjava</b>
 *
 * @author Brian Wellington
 * @author Paul Cowan (pwc21@yahoo.com)
 */
@Slf4j
public class DNSJavaNameService implements NameService {

  private static final String nsProperty = "sun.net.spi.nameservice.nameservers";
  private static final String domainProperty = "sun.net.spi.nameservice.domain";
  private static final String v6Property = "java.net.preferIPv6Addresses";

  private boolean preferV6 = false;

  private Name localhostName = null;
  private InetAddress[] localhostNamedAddresses = null;
  private InetAddress[] localhostAddresses = null;
  private boolean addressesLoaded = false;

  /**
   * Creates a DNSJavaNameService instance.
   *
   * <p>Uses the <b>sun.net.spi.nameservice.nameservers</b>, <b>sun.net.spi.nameservice.domain</b>,
   * and <b>java.net.preferIPv6Addresses</b> properties for configuration.
   */
  protected DNSJavaNameService() {
    String nameServers = System.getProperty(nsProperty);
    String domain = System.getProperty(domainProperty);
    String v6 = System.getProperty(v6Property);

    if (nameServers != null) {
      StringTokenizer st = new StringTokenizer(nameServers, ",");
      String[] servers = new String[st.countTokens()];
      int n = 0;
      while (st.hasMoreTokens()) {
        servers[n++] = st.nextToken();
      }
      try {
        Resolver res = new ExtendedResolver(servers);
        Lookup.setDefaultResolver(res);
      } catch (UnknownHostException e) {
        log.error("DNSJavaNameService: invalid {}", nsProperty);
      }
    }

    if (domain != null) {
      try {
        Lookup.setDefaultSearchPath(new String[] {domain});
      } catch (TextParseException e) {
        log.error("DNSJavaNameService: invalid {}", domainProperty);
      }
    }

    if (v6 != null && v6.equalsIgnoreCase("true")) {
      preferV6 = true;
    }

    try {
      // retrieve the name from the system that is used as localhost
      Class<?> inetAddressImplFactoryClass = Class.forName("java.net.InetAddressImplFactory");
      Method createMethod = inetAddressImplFactoryClass.getDeclaredMethod("create");
      createMethod.setAccessible(true);

      Object inetAddressImpl = createMethod.invoke(null);
      Class<?> inetAddressImplClass = Class.forName("java.net.InetAddressImpl");
      Method hostnameMethod = inetAddressImplClass.getMethod("getLocalHostName");
      hostnameMethod.setAccessible(true);

      localhostName = Name.fromString((String) hostnameMethod.invoke(inetAddressImpl));
      Method lookupAllHostAddrMethod =
          inetAddressImplClass.getMethod("lookupAllHostAddr", String.class);
      lookupAllHostAddrMethod.setAccessible(true);

      localhostNamedAddresses =
          (InetAddress[]) lookupAllHostAddrMethod.invoke(inetAddressImpl, localhostName.toString());
      localhostAddresses =
          (InetAddress[]) lookupAllHostAddrMethod.invoke(inetAddressImpl, "localhost");
      addressesLoaded = true;
    } catch (Exception e) {
      log.error("Could not obtain localhost", e);
    }
  }

  /**
   * Performs a forward DNS lookup for the host name.
   *
   * @param host The host name to resolve.
   * @return All the ip addresses found for the host name.
   */
  public InetAddress[] lookupAllHostAddr(String host) throws UnknownHostException {
    Name name;
    try {
      name = new Name(host);
    } catch (TextParseException e) {
      throw new UnknownHostException(host);
    }

    // avoid asking a dns server (causing a probable timeout) when host is the name of the local
    // host
    if (addressesLoaded) {
      if (name.equals(localhostName)) {
        return localhostNamedAddresses;
      } else if ("localhost".equalsIgnoreCase(host)) {
        return localhostAddresses;
      }
    }

    Record[] records = null;
    if (preferV6) {
      records = new Lookup(name, Type.AAAA).run();
    }
    if (records == null) {
      records = new Lookup(name, Type.A).run();
    }
    if (records == null && !preferV6) {
      records = new Lookup(name, Type.AAAA).run();
    }
    if (records == null) {
      throw new UnknownHostException(host);
    }

    InetAddress[] array = new InetAddress[records.length];
    for (int i = 0; i < records.length; i++) {
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
   *
   * @param addr The ip address to lookup.
   * @return The host name found for the ip address.
   */
  public String getHostByAddr(byte[] addr) throws UnknownHostException {
    Name name = ReverseMap.fromAddress(InetAddress.getByAddress(addr));
    Record[] records = new Lookup(name, Type.PTR).run();
    if (records == null) {
      throw new UnknownHostException("Unknown address: " + name);
    }
    return ((PTRRecord) records[0]).getTarget().toString();
  }
}
