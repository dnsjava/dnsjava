// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.spi;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider.Configuration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

@Slf4j
class DnsjavaInetAddressResolver implements InetAddressResolver {
  private static final String PREFER_V6_PROPERTY = "java.net.preferIPv6Addresses";

  private final boolean preferV6;
  private final Configuration configuration;

  DnsjavaInetAddressResolver(Configuration configuration) {
    log.info("Enabling dnsjava SPI");
    this.configuration = configuration;
    preferV6 = Boolean.getBoolean(PREFER_V6_PROPERTY);
  }

  @Override
  public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy)
      throws UnknownHostException {
    // delegate local hostnames to the default resolver - we don't know them any better
    // and this shouldn't leak anything either
    if (host.equalsIgnoreCase(configuration.lookupLocalHostName())
        || "localhost".equalsIgnoreCase(host)) {
      return configuration.builtinResolver().lookupByName(host, lookupPolicy);
    }

    Name name;
    try {
      name = new Name(host);
    } catch (TextParseException e) {
      throw new UnknownHostException(host);
    }

    List<InetAddress> results = new ArrayList<>(8);
    boolean ranIpV4 = false;
    boolean ranIpV6 = false;

    int characteristics = lookupPolicy.characteristics();
    // fallback to default policy if no specific preference has been set
    if ((characteristics & (LookupPolicy.IPV6_FIRST | LookupPolicy.IPV4_FIRST)) == 0) {
      if (preferV6) {
        characteristics |= LookupPolicy.IPV6_FIRST;
      } else {
        characteristics |= LookupPolicy.IPV4_FIRST;
      }
    }
    if ((characteristics & LookupPolicy.IPV6) == LookupPolicy.IPV6
        && (characteristics & LookupPolicy.IPV6_FIRST) == LookupPolicy.IPV6_FIRST) {
      Record[] records = new Lookup(name, Type.AAAA).run();
      if (records != null) {
        for (Record r : records) {
          results.add(((AAAARecord) r).getAddress());
        }
      }
      ranIpV6 = true;
    }
    if ((characteristics & LookupPolicy.IPV4) == LookupPolicy.IPV4
        && (characteristics & LookupPolicy.IPV4_FIRST) == LookupPolicy.IPV4_FIRST) {
      Record[] records = new Lookup(name, Type.A).run();
      if (records != null) {
        for (Record r : records) {
          results.add(((ARecord) r).getAddress());
        }
      }
      ranIpV4 = true;
    }
    if ((characteristics & LookupPolicy.IPV4) == LookupPolicy.IPV4 && !ranIpV4) {
      Record[] records = new Lookup(name, Type.A).run();
      if (records != null) {
        for (Record r : records) {
          results.add(((ARecord) r).getAddress());
        }
      }
    }
    if ((characteristics & LookupPolicy.IPV6) == LookupPolicy.IPV6 && !ranIpV6) {
      Record[] records = new Lookup(name, Type.AAAA).run();
      if (records != null) {
        for (Record r : records) {
          results.add(((AAAARecord) r).getAddress());
        }
      }
    }
    if (results.isEmpty()) {
      throw new UnknownHostException(host);
    }

    return results.stream();
  }

  @Override
  public String lookupByAddress(byte[] addr) throws UnknownHostException {
    Name name = ReverseMap.fromAddress(InetAddress.getByAddress(addr));
    Record[] records = new Lookup(name, Type.PTR).run();
    if (records == null) {
      throw new UnknownHostException("Unknown address: " + name);
    }
    return ((PTRRecord) records[0]).getTarget().toString();
  }
}
