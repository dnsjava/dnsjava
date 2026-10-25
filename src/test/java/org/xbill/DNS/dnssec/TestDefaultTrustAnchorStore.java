// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;

class TestDefaultTrustAnchorStore {
  @Test
  void testNullKeyWhenNameNotUnderAnchor() throws TextParseException {
    DefaultTrustAnchorStore tas = new DefaultTrustAnchorStore();
    RRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
    assertThat(anchor).isNull();
  }

  @Test
  void testKeyWhenNameUnderAnchorDS() throws TextParseException {
    SRRset set =
        new SRRset(new DSRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    DefaultTrustAnchorStore tas = new DefaultTrustAnchorStore();
    tas.store(set);
    RRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
    assertThat(anchor).isEqualTo(set);
  }

  @Test
  void testKeyWhenNameUnderAnchorDNSKEY() throws TextParseException {
    SRRset set =
        new SRRset(
            new DNSKEYRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    DefaultTrustAnchorStore tas = new DefaultTrustAnchorStore();
    tas.store(set);
    RRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
    assertThat(anchor).isNotNull();
    assertThat(anchor.getName()).isEqualTo(set.getName());
  }

  @Test
  void testInvalidAnchorRecord() throws TextParseException {
    SRRset set = new SRRset(new TXTRecord(Name.fromString("bla."), DClass.IN, 0, "root"));
    DefaultTrustAnchorStore tas = new DefaultTrustAnchorStore();
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> tas.store(set));
  }

  @Test
  void testClear() throws TextParseException {
    SRRset set =
        new SRRset(
            new DNSKEYRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    DefaultTrustAnchorStore tas = new DefaultTrustAnchorStore();
    tas.store(set);
    RRset anchor = tas.find(Name.fromString("asdf.bla."), DClass.IN);
    assertThat(anchor).isNotNull();
    tas.clear();
    assertThat(tas.find(Name.fromString("asdf.bla."), DClass.IN)).isNull();
  }

  @Test
  void testCaseInsensitiveAnchor() throws TextParseException {
    DefaultTrustAnchorStore tas = new DefaultTrustAnchorStore();
    SRRset set1 =
        new SRRset(new DSRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    SRRset set2 =
        new SRRset(new DSRecord(Name.fromString("Bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    tas.store(set1);
    tas.store(set2);
    RRset anchor = tas.find(Name.fromString("bla."), DClass.IN);
    assertThat(anchor).isEqualTo(set2);
    assertThat(tas.items()).containsExactly(set2);
  }

  @Test
  void testCaseInsensitiveSameSetAnchor() throws TextParseException {
    DefaultTrustAnchorStore tas = new DefaultTrustAnchorStore();
    SRRset set = new SRRset();
    set.addRR(new DSRecord(Name.fromString("Bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    set.addRR(new DSRecord(Name.fromString("bla."), DClass.IN, 0, 0, 0, 0, new byte[] {0}));
    tas.store(set);
    RRset anchor = tas.find(Name.fromString("bla."), DClass.IN);
    assertThat(anchor).isEqualTo(set);
    assertThat(tas.items()).containsExactly(set);
  }
}
