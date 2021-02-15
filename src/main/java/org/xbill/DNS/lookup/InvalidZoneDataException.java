// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

/**
 * Sometimes DNS zone data involved in the lookup might be violating specifications. For example, a
 * DNAME expansion might result in names that are too long or a query response might hold multiple
 * CNAME records.
 */
public class InvalidZoneDataException extends LookupFailedException {
  public InvalidZoneDataException(String message) {
    super(message);
  }
}
