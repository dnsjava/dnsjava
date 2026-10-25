// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.IOException;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.EDNSOption.Code;

class DnssecAlgorithmOptionTest {
  @Test
  void ctor() {
    new DnssecAlgorithmOption(Code.DAU);
    new DnssecAlgorithmOption(Code.DHU);
    new DnssecAlgorithmOption(Code.N3U);

    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new DnssecAlgorithmOption(4));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new DnssecAlgorithmOption(8));
  }

  @Test
  void ctorOptionsEmpty() {
    DnssecAlgorithmOption o = new DnssecAlgorithmOption(Code.DAU);
    assertThat(o.getAlgorithms()).isEmpty();
  }

  @Test
  void ctorOptionsList() {
    DnssecAlgorithmOption o =
        new DnssecAlgorithmOption(Code.DAU, Collections.singletonList(Algorithm.RSASHA1));
    assertThat(o.getAlgorithms()).hasSize(1);
  }

  @Test
  void ctorOptionsVarargs() {
    DnssecAlgorithmOption o = new DnssecAlgorithmOption(Code.DAU, Algorithm.RSASHA1);
    assertThat(o.getAlgorithms()).hasSize(1);
  }

  @Test
  void ctorOptionsVarargsNull() {
    DnssecAlgorithmOption o = new DnssecAlgorithmOption(Code.DAU, (int[]) null);
    assertThat(o.getAlgorithms()).isEmpty();
  }

  @Test
  void parse() throws IOException {
    DNSInput in = new DNSInput(new byte[] {0, 5, 0, 2, 5, 6});
    DnssecAlgorithmOption o = (DnssecAlgorithmOption) EDNSOption.fromWire(in);
    assertThat(o.getAlgorithms().get(0)).isEqualTo(Algorithm.RSASHA1);
    assertThat(o.getAlgorithms().get(1)).isEqualTo(Algorithm.DSA_NSEC3_SHA1);
  }

  @Test
  void write() {
    DnssecAlgorithmOption o =
        new DnssecAlgorithmOption(Code.DAU, Algorithm.RSASHA1, Algorithm.DSA_NSEC3_SHA1);
    DNSOutput out = new DNSOutput();
    o.toWire(out);
    assertThat(out.toByteArray()).containsExactly(new byte[] {0, 5, 0, 2, 5, 6});
  }

  @Test
  void testToString() {
    DnssecAlgorithmOption o =
        new DnssecAlgorithmOption(Code.DAU, Algorithm.RSASHA1, Algorithm.DSA_NSEC3_SHA1);
    assertThat(o.optionToString()).isEqualTo("[RSASHA1, DSA-NSEC3-SHA1]");
  }
}
