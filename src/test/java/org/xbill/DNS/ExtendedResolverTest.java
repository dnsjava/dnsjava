// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

class ExtendedResolverTest {
  @Test
  void testGetExtendedResolver() throws UnknownHostException {
    ExtendedResolver r = new ExtendedResolver(new SimpleResolver[] {new SimpleResolver("0.0.0.0")});
    assertThat(r.getResolvers()).hasSize(1);
  }
}
