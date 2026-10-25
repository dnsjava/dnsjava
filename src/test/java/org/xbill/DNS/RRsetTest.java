// SPDX-License-Identifier: BSD-3-Clause
// -*- Java -*-
//
// Copyright (c) 2005, Matthew J. Rutherford <rutherfo@cs.colorado.edu>
// Copyright (c) 2005, University of Colorado at Boulder
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of the University of Colorado at Boulder nor the
//   names of its contributors may be used to endorse or promote
//   products derived from this software without specific prior written
//   permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RRsetTest {
  private RRset m_rs;
  private Name m_name;
  private Name m_name2;
  private long m_ttl;
  private ARecord m_a1;
  private ARecord m_a2;
  private RRSIGRecord m_s1;
  private RRSIGRecord m_s2;

  @BeforeEach
  void setUp() throws TextParseException, UnknownHostException {
    m_rs = new RRset();
    m_name = Name.fromString("this.is.a.test.");
    m_name2 = Name.fromString("this.is.another.test.");
    m_ttl = 0xABCDL;
    m_a1 = new ARecord(m_name, DClass.IN, m_ttl, InetAddress.getByName("192.169.232.11"));
    m_a2 = new ARecord(m_name, DClass.IN, m_ttl + 1, InetAddress.getByName("192.169.232.12"));

    m_s1 =
        new RRSIGRecord(
            m_name,
            DClass.IN,
            m_ttl,
            Type.A,
            0xF,
            0xABCDEL,
            Instant.now(),
            Instant.now(),
            0xA,
            m_name,
            new byte[] {1});
    m_s2 =
        new RRSIGRecord(
            m_name,
            DClass.IN,
            m_ttl,
            Type.A,
            0xF,
            0xABCDEL,
            Instant.now(),
            Instant.now(),
            0xA,
            m_name2,
            new byte[] {1});
  }

  @Test
  void ctor_0arg() {
    assertThat(m_rs.size()).isZero();
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_rs.getDClass());
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_rs.getType());
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_rs.getTTL());
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_rs.getName());
    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> m_rs.first());

    assertThat(m_rs).hasToString("{empty}");

    List<Record> rrs = m_rs.rrs();
    assertThat(rrs).isNotNull().isEmpty();

    List<RRSIGRecord> sigs = m_rs.sigs();
    assertThat(sigs).isNotNull().isEmpty();
  }

  @Test
  void basics() {
    m_rs.addRR(m_a1);

    assertThat(m_rs).hasSize(1);
    assertThat(m_rs.getDClass()).isEqualTo(DClass.IN);
    assertThat(m_rs.first()).isEqualTo(m_a1);
    assertThat(m_rs.getName()).isEqualTo(m_name);
    assertThat(m_rs.getTTL()).isEqualTo(m_ttl);
    assertThat(m_rs.getType()).isEqualTo(Type.A);

    // add it again, and make sure nothing changed
    m_rs.addRR(m_a1);

    assertThat(m_rs).hasSize(1);
    assertThat(m_rs.getDClass()).isEqualTo(DClass.IN);
    assertThat(m_rs.first()).isEqualTo(m_a1);
    assertThat(m_rs.getName()).isEqualTo(m_name);
    assertThat(m_rs.getTTL()).isEqualTo(m_ttl);
    assertThat(m_rs.getType()).isEqualTo(Type.A);

    m_rs.addRR(m_a2);

    assertThat(m_rs.size()).isEqualTo(2);
    assertThat(m_rs.getDClass()).isEqualTo(DClass.IN);
    Record r = m_rs.first();
    assertThat(r).isEqualTo(m_a1);
    assertThat(m_rs.getName()).isEqualTo(m_name);
    assertThat(m_rs.getTTL()).isEqualTo(m_ttl);
    assertThat(m_rs.getType()).isEqualTo(Type.A);

    List<Record> itr = m_rs.rrs();
    assertThat(itr.get(0)).isEqualTo(m_a1);
    assertThat(itr.get(1)).isEqualTo(m_a2);

    // make sure that it rotates
    itr = m_rs.rrs();
    assertThat(itr.get(0)).isEqualTo(m_a2);
    assertThat(itr.get(1)).isEqualTo(m_a1);
    itr = m_rs.rrs();
    assertThat(itr.get(0)).isEqualTo(m_a1);
    assertThat(itr.get(1)).isEqualTo(m_a2);

    m_rs.deleteRR(m_a1);
    assertThat(m_rs).hasSize(1);
    assertThat(m_rs.getDClass()).isEqualTo(DClass.IN);
    assertThat(m_rs.first()).isEqualTo(m_a2);
    assertThat(m_rs.getName()).isEqualTo(m_name);
    assertThat(m_rs.getTTL()).isEqualTo(m_ttl);
    assertThat(m_rs.getType()).isEqualTo(Type.A);

    // the signature records
    m_rs.addRR(m_s1);
    assertThat(m_rs).hasSize(1);
    List<RRSIGRecord> sigs = m_rs.sigs();
    assertThat(sigs.get(0)).isEqualTo(m_s1);
    assertThat(sigs).hasSize(1);

    m_rs.addRR(m_s1);
    sigs = m_rs.sigs();
    assertThat(sigs.get(0)).isEqualTo(m_s1);
    assertThat(sigs).hasSize(1);

    m_rs.addRR(m_s2);
    sigs = m_rs.sigs();
    assertThat(sigs.get(0)).isEqualTo(m_s1);
    assertThat(sigs.get(1)).isEqualTo(m_s2);
    assertThat(sigs).hasSize(2);

    m_rs.deleteRR(m_s1);
    sigs = m_rs.sigs();
    assertThat(sigs.get(0)).isEqualTo(m_s2);
    assertThat(sigs).hasSize(1);

    // clear it all
    m_rs.clear();
    assertThat(m_rs.size()).isZero();
    assertThat(m_rs.rrs()).isEmpty();
    assertThat(m_rs.sigs()).isEmpty();
  }

  @Test
  void ctor_1arg() {
    m_rs.addRR(m_a1);
    m_rs.addRR(m_a2);
    m_rs.addRR(m_s1);
    m_rs.addRR(m_s2);

    RRset rs2 = new RRset(m_rs);

    assertThat(rs2.size()).isEqualTo(2);
    assertThat(rs2.first()).isEqualTo(m_a1);
    List<Record> itr = rs2.rrs();
    assertThat(itr.get(0)).isEqualTo(m_a1);
    assertThat(itr.get(1)).isEqualTo(m_a2);
    assertThat(itr).hasSize(2);

    List<RRSIGRecord> sigs = rs2.sigs();
    assertThat(sigs.get(0)).isEqualTo(m_s1);
    assertThat(sigs.get(1)).isEqualTo(m_s2);
    assertThat(sigs).hasSize(2);
  }

  @Test
  void ctor_vararg() {
    RRset set = new RRset(m_a1, m_a2);
    assertThat(set.rrs()).isEqualTo(Stream.of(m_a1, m_a2).collect(Collectors.toList()));
    assertThat(set.sigs()).isEqualTo(Collections.emptyList());
  }

  @Test
  void ctor_vararg_sig() {
    RRset set = new RRset(m_a1, m_a2, m_s1);
    assertThat(set.rrs()).isEqualTo(Stream.of(m_a1, m_a2).collect(Collectors.toList()));
    assertThat(set.sigs()).isEqualTo(Collections.singletonList(m_s1));
  }

  @Test
  void ctor_vararg_mismatch() {
    TXTRecord txt = new TXTRecord(m_name, DClass.IN, 3600, "test");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new RRset(m_a1, m_a2, txt));
  }

  @Test
  void ctor_vararg_null() {
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new RRset((Record[]) null));
  }

  @Test
  void test_toString() {
    m_rs.addRR(m_a1);
    m_rs.addRR(m_a2);
    m_rs.addRR(m_s1);
    m_rs.addRR(m_s2);

    String out = m_rs.toString();

    assertThat(out)
        .contains(m_name.toString())
        .contains(" IN A ")
        .contains("[192.169.232.11]")
        .contains("[192.169.232.12]");
  }

  @Test
  void test_toStringOnlySig() {
    m_rs.addRR(m_s1);

    String out = m_rs.toString();

    assertThat(out).doesNotContain("{empty}").contains(" sigs: ").contains(m_name.toString());
  }

  @Test
  void test_toStringEmpty() {
    assertThat(m_rs).hasToString("{empty}");
  }

  @Test
  void addRR_invalidType() throws TextParseException {
    m_rs.addRR(m_a1);

    CNAMERecord c = new CNAMERecord(m_name, DClass.IN, m_ttl, Name.fromString("an.alias."));

    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_rs.addRR(c));
  }

  @Test
  void addRR_invalidName() throws UnknownHostException {
    m_rs.addRR(m_a1);

    m_a2 = new ARecord(m_name2, DClass.IN, m_ttl, InetAddress.getByName("192.169.232.11"));

    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_rs.addRR(m_a2));
  }

  @Test
  void addRR_invalidDClass() throws UnknownHostException {
    m_rs.addRR(m_a1);

    m_a2 = new ARecord(m_name, DClass.CHAOS, m_ttl, InetAddress.getByName("192.169.232.11"));

    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_rs.addRR(m_a2));
  }

  @Test
  void TTLcalculation() {
    m_rs.addRR(m_a2);
    assertThat(m_rs.getTTL()).isEqualTo(m_a2.getTTL());
    m_rs.addRR(m_a1);
    assertThat(m_rs.getTTL()).isEqualTo(m_a1.getTTL());

    for (Record r : m_rs.rrs()) {
      assertThat(r.getTTL()).isEqualTo(m_a1.getTTL());
    }
  }

  @Test
  void Record_placement() {
    m_rs.addRR(m_a1);
    m_rs.addRR(m_s1);
    m_rs.addRR(m_a2);

    List<Record> itr = m_rs.rrs();
    assertThat(itr.get(0)).isEqualTo(m_a1);
    assertThat(itr.get(1)).isEqualTo(m_a2);
    assertThat(itr).hasSize(2);

    List<RRSIGRecord> sigs = m_rs.sigs();
    assertThat(sigs.get(0)).isEqualTo(m_s1);
    assertThat(sigs).hasSize(1);
  }

  @Test
  void noncycling_iterator() {
    m_rs.addRR(m_a1);
    m_rs.addRR(m_a2);

    List<Record> itr = m_rs.rrs(false);
    assertThat(itr.get(0)).isEqualTo(m_a1);
    assertThat(itr.get(1)).isEqualTo(m_a2);

    itr = m_rs.rrs(false);
    assertThat(itr.get(0)).isEqualTo(m_a1);
    assertThat(itr.get(1)).isEqualTo(m_a2);
  }

  @ParameterizedTest
  @ValueSource(ints = {100, 50_000})
  void cycleSimulationShortValues(int numOfCalls) {
    RRset rrset = new RRset();
    rrset.addRR(m_a1);
    rrset.addRR(m_a2);

    assertDoesNotThrow(
        () -> {
          for (int i = 0; i < numOfCalls; i++) {
            rrset.rrs(true);
          }
        });
  }
}
