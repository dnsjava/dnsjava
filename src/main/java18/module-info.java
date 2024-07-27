// SPDX-License-Identifier: BSD-3-Clause

import java.net.spi.InetAddressResolverProvider;
import org.xbill.DNS.spi.DnsjavaInetAddressResolverProvider;

module org.dnsjava {
  requires static lombok;
  requires static java.naming;
  requires static com.sun.jna;
  requires static com.sun.jna.platform;
  requires static java.net.http;
  requires org.slf4j;

  exports org.xbill.DNS;
  exports org.xbill.DNS.config;
  exports org.xbill.DNS.dnssec;
  exports org.xbill.DNS.hosts;
  exports org.xbill.DNS.lookup;
  exports org.xbill.DNS.tools;
  exports org.xbill.DNS.utils;

  provides InetAddressResolverProvider with
      DnsjavaInetAddressResolverProvider;
}
