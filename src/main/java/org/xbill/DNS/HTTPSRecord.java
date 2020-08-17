// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.util.List;

/**
 * HTTPS Service Location and Parameter Binding Record
 *
 * @see <a
 *     href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01">draft-ietf-dnsop-svcb-https</a>
 */
public class HTTPSRecord extends SVCBBase {
  HTTPSRecord() {}

  public HTTPSRecord(
      Name name, int dclass, long ttl, int priority, Name domain, List<ParameterBase> params) {
    super(name, Type.HTTPS, dclass, ttl, priority, domain, params);
  }
}
