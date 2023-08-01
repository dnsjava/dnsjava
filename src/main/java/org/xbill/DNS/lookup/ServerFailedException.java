// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

/**
 * Represents a server failure, that the upstream server responding to the request returned a {@link
 * org.xbill.DNS.Rcode#SERVFAIL} status.
 */
public class ServerFailedException extends LookupFailedException {}
