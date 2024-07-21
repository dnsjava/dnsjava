// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.util.List;

/**
 * Service Location and Parameter Binding Record
 *
 * @since 3.3
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9460">RFC 9460</a>
 */
public class SVCBRecord extends SVCBBase {
  SVCBRecord() {}

  public SVCBRecord(
      Name name, int dclass, long ttl, int priority, Name domain, List<ParameterBase> params) {
    super(name, Type.SVCB, dclass, ttl, priority, domain, params);
  }
}
