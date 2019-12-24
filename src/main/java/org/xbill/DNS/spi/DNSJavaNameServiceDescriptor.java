// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.spi;

import sun.net.spi.nameservice.NameService;
import sun.net.spi.nameservice.NameServiceDescriptor;

/**
 * The descriptor class for the dnsjava name service provider.
 *
 * @author Brian Wellington
 * @author Paul Cowan (pwc21@yahoo.com)
 */
public class DNSJavaNameServiceDescriptor implements NameServiceDescriptor {
  /** Returns a reference to a dnsjava name server provider. */
  @Override
  public NameService createNameService() {
    return new DNSJavaNameService();
  }

  @Override
  public String getType() {
    return "dns";
  }

  @Override
  public String getProviderName() {
    return "dnsjava";
  }
}
