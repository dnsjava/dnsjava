// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TestByteArrayComparator {
  private final byte[] b1 = {0};
  private final byte[] b2 = {0};
  private final byte[] b3 = {1};
  private final byte[] b4 = {1, 0};

  @Test
  void testEquals() {
    assertThat(ByteArrayComparator.compare(b1, b2)).isZero();
  }

  @Test
  void testLessThan() {
    assertThat(ByteArrayComparator.compare(b2, b3)).isEqualTo(-1);
    assertThat(ByteArrayComparator.compare(b1, b4)).isEqualTo(-1);
  }

  @Test
  void testGreaterThan() {
    assertThat(ByteArrayComparator.compare(b3, b2)).isOne();
    assertThat(ByteArrayComparator.compare(b4, b1)).isOne();
  }
}
