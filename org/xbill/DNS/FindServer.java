// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

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
 * As of dnsjava 1.6.6, all functions in this class are wrappers
 * around functions in the ResolverConfig class, and those should be
 * used instead.
 *
 * @see ResolverConfig
 *
 * @author Brian Wellington
 */

public class FindServer {

static {
	ResolverConfig.getCurrentConfig();
}

private
FindServer() {}

/** Returns all located servers */
public static String []
servers() {
	return ResolverConfig.getCurrentConfig().servers();
}

/** Returns the first located server */
public static String
server() {
	return ResolverConfig.getCurrentConfig().server();
}

/** Returns all entries in the located search path */
public static Name []
searchPath() {
	return ResolverConfig.getCurrentConfig().searchPath();
}

}
