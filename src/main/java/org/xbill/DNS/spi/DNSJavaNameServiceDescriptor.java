// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.spi;

import java.lang.reflect.Proxy;

import sun.net.spi.nameservice.*;

/**
 * The descriptor class for the dnsjava name service provider.
 *
 * @author Brian Wellington
 * @author Paul Cowan (pwc21@yahoo.com)
 */
public class DNSJavaNameServiceDescriptor implements NameServiceDescriptor {

private static NameService nameService;

static {
	ClassLoader loader = NameService.class.getClassLoader();
	if (loader == null) {
		loader = Thread.currentThread().getContextClassLoader();
	}
	nameService = (NameService) Proxy.newProxyInstance(loader,
			new Class[] { NameService.class },
			new DNSJavaNameService());
}

/**
 * Returns a reference to a dnsjava name server provider.
 */
@Override
public NameService
createNameService() {
	return nameService;
}

@Override
public String
getType() {
	return "dns";
}

@Override
public String
getProviderName() {
	return "dnsjava"; 
}

}
