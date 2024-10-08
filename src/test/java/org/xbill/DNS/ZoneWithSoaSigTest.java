// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.Test;

class ZoneWithSoaSigTest {
  @Test
  void canParseZoneWithSigs() throws IOException {
    Name an = Name.fromString("10.in-addr.arpa.");
    Name host = Name.fromString("z.example.com.");
    Name secondary = Name.fromString("y.example.com.");
    Name admin = Name.fromString("dns-ops.example.com.");

    long ttl = 86400;
    long serial = 2147483749L;
    long refresh = 1800;
    long retry = 900;
    long expire = 691200;
    long minimum = 10800;

    // dummy set of records for a dummy zone
    Record[] records =
        new Record[] {
          new SOARecord(an, DClass.IN, ttl, host, admin, serial, refresh, retry, expire, minimum),
          new NSRecord(an, DClass.IN, ttl, host),
          new NSRecord(an, DClass.IN, ttl, secondary),
          new DNSKEYRecord(
              an, DClass.IN, ttl, 256, 3, 5, "dummypublickey".getBytes(StandardCharsets.UTF_8)),
          new RRSIGRecord(
              an,
              DClass.IN,
              ttl,
              Type.NS,
              5,
              ttl,
              Instant.now(),
              Instant.now(),
              5,
              an,
              "dummysig1".getBytes(StandardCharsets.UTF_8)),
          new RRSIGRecord(
              an,
              DClass.IN,
              ttl,
              Type.SOA,
              5,
              ttl,
              Instant.now(),
              Instant.now(),
              5,
              an,
              "dummysig2".getBytes(StandardCharsets.UTF_8))
        };

    Zone z = new Zone(an, records);
    List<RRset> rrSets = StreamSupport.stream(z.spliterator(), false).collect(Collectors.toList());

    // there should be 3 RRsets (soa, ns, dskey)
    assertThat(rrSets).hasSize(3);

    // assert that there is 1 SOA and it is signed
    List<RRset> allSoaSets =
        rrSets.stream().filter(r -> r.getType() == Type.SOA).collect(Collectors.toList());
    assertThat(allSoaSets).hasSize(1);
    RRset onlySoaSet = allSoaSets.get(0);
    assertThat(onlySoaSet.rrs()).hasSize(1);
    assertThat(onlySoaSet.sigs()).hasSize(1);

    // assert that there are 2 nameservers and they are signed
    List<RRset> allNsSets =
        rrSets.stream().filter(r -> r.getType() == Type.NS).collect(Collectors.toList());
    RRset onlyNsSet = allNsSets.get(0);
    assertThat(onlyNsSet.rrs()).hasSize(2);
    assertThat(onlyNsSet.sigs()).hasSize(1);

    // assert that there is 1 dskey and it is not signed
    List<RRset> allKeySets =
        rrSets.stream().filter(r -> r.getType() == Type.DNSKEY).collect(Collectors.toList());
    RRset onlyKeySet = allKeySets.get(0);
    assertThat(onlyKeySet.rrs()).hasSize(1);
    assertThat(onlyKeySet.sigs()).isEmpty();
  }

  @Test
  void canReplaceSoa() throws IOException {
    Name an = Name.fromString("10.in-addr.arpa.");
    Name host = Name.fromString("z.example.com.");
    Name secondary = Name.fromString("y.example.com.");
    Name admin = Name.fromString("dns-ops.example.com.");
    Name admin2 = Name.fromString("dns-ops2.example.com.");

    long ttl = 86400;
    long serial = 2147483749L;
    long refresh = 1800;
    long retry = 900;
    long expire = 691200;
    long minimum = 10800;

    Record soa =
        new SOARecord(an, DClass.IN, ttl, host, admin, serial, refresh, retry, expire, minimum);
    Record soaRrsig =
        new RRSIGRecord(
            an,
            DClass.IN,
            ttl,
            Type.SOA,
            5,
            ttl,
            Instant.now(),
            Instant.now(),
            5,
            an,
            "soa1Sig".getBytes(StandardCharsets.UTF_8));

    // for otherSoa, admin is different than the original
    Record otherSoa =
        new SOARecord(an, DClass.IN, ttl, host, admin2, serial, refresh, retry, expire, minimum);
    // for anotherSoaRrsig sig is different from the original
    Record anotherSoaRrsig =
        new RRSIGRecord(
            an,
            DClass.IN,
            ttl,
            Type.SOA,
            5,
            ttl,
            Instant.now(),
            Instant.now(),
            5,
            an,
            "soa2sig".getBytes(StandardCharsets.UTF_8));

    Record nsSig =
        new RRSIGRecord(
            an,
            DClass.IN,
            ttl,
            Type.NS,
            5,
            ttl,
            Instant.now(),
            Instant.now(),
            5,
            an,
            "nsSig".getBytes(StandardCharsets.UTF_8));

    // dummy set of records for a dummy zone
    Record[] records =
        new Record[] {
          soa,
          new NSRecord(an, DClass.IN, ttl, host),
          new NSRecord(an, DClass.IN, ttl, secondary),
          new DNSKEYRecord(
              an, DClass.IN, ttl, 256, 3, 5, "dummypublickey".getBytes(StandardCharsets.UTF_8)),
          nsSig,
          soaRrsig
        };

    Zone z = new Zone(an, records);
    // replace Soa
    z.addRecord(otherSoa);
    // replace RRSig covering Soa
    z.removeRecord(soaRrsig);
    z.addRecord(anotherSoaRrsig);

    List<RRset> rrSets = StreamSupport.stream(z.spliterator(), false).collect(Collectors.toList());

    // there should be 3 RRsets (soa, ns, dskey)
    assertThat(rrSets).hasSize(3);

    // assert that there is 1 SOA and it is signed
    List<RRset> allSoaSets =
        rrSets.stream().filter(r -> r.getType() == Type.SOA).collect(Collectors.toList());
    assertThat(allSoaSets).hasSize(1);
    RRset onlySoaSet = allSoaSets.get(0);
    assertThat(onlySoaSet.rrs()).hasSize(1);
    assertThat(onlySoaSet.sigs()).hasSize(1);
    // confirm that the SOA was replaced correctly
    assertThat(((SOARecord) onlySoaSet.rrs().get(0)).getAdmin()).isEqualTo(admin2);
    // confirm that the RRSig on the SOA was replaced correctly
    assertThat((onlySoaSet.sigs().get(0)).getSignature())
        .isEqualTo("soa2sig".getBytes(StandardCharsets.UTF_8));

    // assert that there are 2 nameservers and they are signed
    List<RRset> allNsSets =
        rrSets.stream().filter(r -> r.getType() == Type.NS).collect(Collectors.toList());
    RRset onlyNsSet = allNsSets.get(0);
    assertThat(onlyNsSet.rrs()).hasSize(2);
    assertThat(onlyNsSet.sigs()).hasSize(1);

    // assert that there is 1 dskey and it is not signed
    List<RRset> allKeySets =
        rrSets.stream().filter(r -> r.getType() == Type.DNSKEY).collect(Collectors.toList());
    RRset onlyKeySet = allKeySets.get(0);
    assertThat(onlyKeySet.rrs()).hasSize(1);
    assertThat(onlyKeySet.sigs()).isEmpty();
  }
}
