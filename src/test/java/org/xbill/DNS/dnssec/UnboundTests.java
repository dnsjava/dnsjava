// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

@Slf4j
class UnboundTests extends TestBase {
  void runUnboundTest() throws ParseException, IOException {
    try {
      InputStream data = getClass().getResourceAsStream("/unbound/" + testName + ".rpl");
      RplParser p = new RplParser(data);
      Rpl rpl = p.parse();
      Properties config = new Properties();
      if (rpl.nsec3iterations != null) {
        for (Entry<Integer, Integer> e : rpl.nsec3iterations.entrySet()) {
          config.put("dnsjava.dnssec.nsec3.iterations." + e.getKey(), e.getValue());
        }
      }

      if (rpl.digestPreference != null) {
        config.put(ValUtils.DIGEST_PREFERENCE, rpl.digestPreference);
      }

      config.put(ValUtils.DIGEST_HARDEN_DOWNGRADE, Boolean.toString(rpl.hardenAlgoDowngrade));

      if (rpl.enableSha1) {
        config.put(ValUtils.DIGEST_ENABLED + "." + DNSSEC.Digest.SHA1, Boolean.TRUE.toString());
      }

      if (rpl.enableDsa || rpl.enableSha1) {
        config.put(
            ValUtils.ALGORITHM_ENABLED + "." + DNSSEC.Algorithm.DSA, Boolean.TRUE.toString());
        config.put(
            ValUtils.ALGORITHM_ENABLED + "." + DNSSEC.Algorithm.DSA_NSEC3_SHA1,
            Boolean.TRUE.toString());
      }

      if (!rpl.hardenUnknownAdditional) {
        System.setProperty("dnsjava.harden_unknown_additional", Boolean.TRUE.toString());
      }

      if (rpl.loadBouncyCastle) {
        Security.addProvider(new BouncyCastleProvider());
      }

      for (Message m : rpl.replays) {
        add(m);
      }

      // merge xNAME queries into one
      List<Message> copy = new ArrayList<>(rpl.replays.size());
      copy.addAll(rpl.replays);
      List<Name> copiedTargets = new ArrayList<>(5);
      for (Message m : copy) {
        Name target = null;
        for (RRset s : m.getSectionRRsets(Section.ANSWER)) {
          if (s.getType() == Type.CNAME) {
            target = ((CNAMERecord) s.first()).getTarget();
          } else if (s.getType() == Type.DNAME) {
            target = ((DNAMERecord) s.first()).getTarget();
          }

          while (target != null) {
            Message a = get(target, m.getQuestion().getType());
            if (a == null) {
              a = get(target, Type.CNAME);
            }

            if (a == null) {
              a = get(target, Type.DNAME);
            }

            if (a != null) {
              target = add(m, a);
              if (copiedTargets.contains(target)) {
                break;
              }

              copiedTargets.add(target);
              rpl.replays.remove(a);
            } else {
              target = null;
            }
          }
        }
      }

      // promote any DS records in auth. sections to real queries
      copy = new ArrayList<>(rpl.replays.size());
      copy.addAll(rpl.replays);
      for (Message m : copy) {
        for (RRset s : m.getSectionRRsets(Section.AUTHORITY)) {
          if (s.getType() == Type.DS) {
            Message ds = new Message();
            ds.addRecord(
                Record.newRecord(s.getName(), s.getType(), s.getDClass()), Section.QUESTION);
            for (Record rr : s.rrs()) {
              ds.addRecord(rr, Section.ANSWER);
            }

            for (RRSIGRecord sig : s.sigs()) {
              ds.addRecord(sig, Section.ANSWER);
            }

            rpl.replays.add(ds);
          }
        }
      }

      clear();
      for (Message m : rpl.replays) {
        add(m);
      }

      if (rpl.date != null) {
        try {
          when(resolverClock.instant()).thenReturn(rpl.date);
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }

      if (rpl.trustAnchors != null) {
        resolver.getTrustAnchors().clear();
        for (SRRset rrset : rpl.trustAnchors) {
          resolver.getTrustAnchors().store(rrset);
        }
      }

      resolver.init(config);

      for (Check c : rpl.checks.values()) {
        Message s = resolver.send(c.query).normalize(c.query, true);
        log.trace(
            "{}/{}/{} ---> \n{}",
            c.query.getQuestion().getName(),
            Type.string(c.query.getQuestion().getType()),
            DClass.string(c.query.getQuestion().getDClass()),
            s);
        assertEquals(
            c.response.getHeader().getFlag(Flags.AD),
            s.getHeader().getFlag(Flags.AD),
            "AD Flag must match");
        assertEquals(
            Rcode.string(c.response.getRcode()), Rcode.string(s.getRcode()), "RCode must match");
      }
    } finally {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
      System.clearProperty("dnsjava.harden_unknown_additional");
    }
  }

  private Name add(Message target, Message source) {
    Name next = null;
    target.getHeader().setRcode(source.getRcode());
    for (Record r : source.getSection(Section.ANSWER)) {
      target.addRecord(r, Section.ANSWER);
      if (r.getType() == Type.CNAME) {
        next = ((CNAMERecord) r).getTarget();
      } else if (r.getType() == Type.DNAME) {
        next = ((DNAMERecord) r).getTarget();
      }
    }

    for (Record r : source.getSection(Section.AUTHORITY)) {
      if (r.getType() != Type.NS) {
        target.addRecord(r, Section.AUTHORITY);
      }
    }

    return next;
  }

  static void main(String[] xargs) throws IOException, ParseException {
    Map<String, String> ignored =
        new HashMap<String, String>() {
          {
            put("val_faildnskey_ok.rpl", "tests an unbound specific config option");
            put("val_nsec3_nods_negcache.rpl", "we don't do negative caching");
            put("val_unsecds_negcache.rpl", "we don't do negative caching");
            put("val_negcache_dssoa.rpl", "we don't do negative caching");
            put("val_negcache_nodata.rpl", "aggressive NSEC is not supported");
            put("val_negcache_nxdomain.rpl", "aggressive NSEC is not supported");
            put("val_nsec3_b3_optout_negcache.rpl", "we don't do negative caching");
            put("val_dsnsec.rpl", "we don't do negative caching");
            put("val_refer_unsignadd.rpl", "we don't do negative caching");
            put("val_referglue.rpl", "we don't do negative caching");
            put(
                "val_noadwhennodo.rpl",
                "irrelevant - if we wouldn't want AD, we wouldn't be using this stuff");
            put("val_fwdds.rpl", "irrelevant, we're not a recursive resolver");
            put("val_referd.rpl", "NSEC records missing for validation, tests caching stuff");
            put("val_stubds.rpl", "tests unbound specific config (stub zones)");
            put("val_cnametonsec.rpl", "incomplete CNAME answer");
            put("val_cnametooptin.rpl", "incomplete CNAME answer");
            put("val_cnametoinsecure.rpl", "incomplete CNAME answer");
            put("val_nsec3_optout_cache.rpl", "more cache stuff");
            put("val_unsecds_qtypeds.rpl", "tests the iterative resolver");
            put(
                "val_anchor_nx.rpl",
                "tests resolving conflicting responses in a recursive resolver");
            put(
                "val_anchor_nx_nosig.rpl",
                "tests resolving conflicting responses in a recursive resolver");
            put("val_negcache_nta.rpl", "tests unbound option domain-insecure, not available here");
          }
        };

    for (String f : new File("./src/test/resources/unbound").list()) {
      String comment = ignored.get(f);
      if (comment != null) {
        System.out.println("    @Disabled(\"" + comment + "\")");
      }

      Rpl rpl = new RplParser(new FileInputStream("./src/test/resources/unbound/" + f)).parse();
      System.out.println("    @Test");
      System.out.println("    @DisplayName(\"" + f + ": " + rpl.scenario + "\")");
      System.out.println(
          "    void " + f.split("\\.")[0] + "() throws ParseException, IOException {");
      System.out.println("        runUnboundTest();");
      System.out.println("    }");
      System.out.println();
    }
  }

  @Test
  @DisplayName("val_adbit.rpl: Test validator AD bit signaling")
  void val_adbit() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_adcopy.rpl: Test validator AD bit sent by untrusted upstream")
  void val_adcopy() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests resolving conflicting responses in a recursive resolver")
  @Test
  @DisplayName("val_anchor_nx.rpl: Test validator with secure proof of trust anchor nxdomain")
  void val_anchor_nx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests resolving conflicting responses in a recursive resolver")
  @Test
  @DisplayName("val_anchor_nx_nosig.rpl: Test validator with unsigned denial of trust anchor")
  void val_anchor_nx_nosig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ans_dsent.rpl: Test validator with empty nonterminals on the trust chain.")
  void val_ans_dsent() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ans_nx.rpl: Test validator with DS nodata as nxdomain on trust chain")
  void val_ans_nx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_any.rpl: Test validator with response to qtype ANY")
  void val_any() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_any_cname.rpl: Test validator with response to qtype ANY that includes CNAME")
  void val_any_cname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_any_dname.rpl: Test validator with response to qtype ANY that includes DNAME")
  void val_any_dname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnameinsectopos.rpl: Test validator with an insecure cname to positive cached")
  void val_cnameinsectopos() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_cnamenx_dblnsec.rpl: Test validator with cname-nxdomain for duplicate NSEC detection")
  void val_cnamenx_dblnsec() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnamenx_rcodenx.rpl: Test validator with cname-nxdomain with rcode nxdomain")
  void val_cnamenx_rcodenx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnameqtype.rpl: Test validator with a query for type cname")
  void val_cnameqtype() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnametocloser.rpl: Test validator with CNAME to closer anchor under optout.")
  void val_cnametocloser() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_cnametocloser_nosig.rpl: Test validator with CNAME to closer anchor optout missing sigs.")
  void val_cnametocloser_nosig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_cnametocnamewctoposwc.rpl: Test validator with a regular cname to wildcard cname to wildcard response")
  void val_cnametocnamewctoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnametodname.rpl: Test validator with a cname to a dname")
  void val_cnametodname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_cnametodnametocnametopos.rpl: Test validator with cname, dname, cname, positive answer")
  void val_cnametodnametocnametopos() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("incomplete CNAME answer")
  @Test
  @DisplayName("val_cnametoinsecure.rpl: Test validator with CNAME to insecure NSEC or NSEC3.")
  void val_cnametoinsecure() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnametonodata.rpl: Test validator with cname to nodata")
  void val_cnametonodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnametonodata_nonsec.rpl: Test validator with cname to nodata")
  void val_cnametonodata_nonsec() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("incomplete CNAME answer")
  @Test
  @DisplayName("val_cnametonsec.rpl: Test validator with CNAME to insecure NSEC delegation")
  void val_cnametonsec() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnametonx.rpl: Test validator with cname to nxdomain")
  void val_cnametonx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("incomplete CNAME answer")
  @Test
  @DisplayName("val_cnametooptin.rpl: Test validator with CNAME to insecure optin NSEC3")
  void val_cnametooptin() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnametooptout.rpl: Test validator with CNAME to optout NSEC3 span NODATA")
  void val_cnametooptout() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnametopos.rpl: Test validator with a cname to positive")
  void val_cnametopos() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_cnametoposnowc.rpl: Test validator with a cname to positive wildcard without proof")
  void val_cnametoposnowc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnametoposwc.rpl: Test validator with a cname to positive wildcard")
  void val_cnametoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnamewctonodata.rpl: Test validator with wildcard cname to nodata")
  void val_cnamewctonodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnamewctonx.rpl: Test validator with wildcard cname to nxdomain")
  void val_cnamewctonx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cnamewctoposwc.rpl: Test validator with wildcard cname to positive wildcard")
  void val_cnamewctoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cname_loop1.rpl: Test validator with cname loop")
  void val_cname_loop1() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cname_loop2.rpl: Test validator with cname 2 step loop")
  void val_cname_loop2() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_cname_loop3.rpl: Test validator with cname 3 step loop")
  void val_cname_loop3() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_deleg_nons.rpl: Test validator with unsigned delegation with no NS bit in NSEC")
  void val_deleg_nons() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_dnametoolong.rpl: Test validator with a dname too long response")
  void val_dnametoolong() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_dnametopos.rpl: Test validator with a dname to positive")
  void val_dnametopos() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_dnametoposwc.rpl: Test validator with a dname to positive wildcard")
  void val_dnametoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_dnamewc.rpl: Test validator with a wildcarded dname")
  void val_dnamewc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  @DisplayName("val_dsnsec.rpl: Test pickup of DS NSEC from the cache.")
  void val_dsnsec() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ds_afterprime.rpl: Test DS lookup after key prime is done.")
  void val_ds_afterprime() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ds_cname.rpl: Test validator with CNAME response to DS")
  void val_ds_cname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ds_cnamesub.rpl: Test validator with CNAME response to DS in chain of trust")
  void val_ds_cnamesub() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_ds_cnamesubbogus.rpl: Test validator with bogus CNAME response to DS in chain of trust")
  void val_ds_cnamesubbogus() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ds_gost.rpl: Test validator with GOST DS digest")
  void val_ds_gost() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ds_gost_downgrade.rpl: Test validator with GOST DS digest downgrade attack")
  void val_ds_gost_downgrade() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ds_sha2.rpl: Test validator with SHA256 DS digest")
  void val_ds_sha2() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ds_sha2_downgrade.rpl: Test validator with SHA256 DS downgrade to SHA1")
  void val_ds_sha2_downgrade() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_ds_sha2_downgrade_override.rpl: Test validator with SHA256 DS downgrade to SHA1")
  void val_ds_sha2_downgrade_override() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ds_sha2_lenient.rpl: Test validator with SHA256 DS downgrade to SHA1 lenience")
  void val_ds_sha2_lenient() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_entds.rpl: Test validator with lots of ENTs in the chain of trust")
  void val_entds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_faildnskey.rpl: Test validator with failed DNSKEY request")
  void val_faildnskey() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests an unbound specific config option")
  @Test
  @DisplayName(
      "val_faildnskey_ok.rpl: Test validator with failed DNSKEY request, but not hardened.")
  void val_faildnskey_ok() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("irrelevant, we're not a recursive resolver")
  @Test
  @DisplayName("val_fwdds.rpl: Test forward-zone with DS query")
  void val_fwdds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_keyprefetch.rpl: Test validator with key prefetch")
  void val_keyprefetch() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_keyprefetch_verify.rpl: Test validator with key prefetch and verify with the anchor")
  void val_keyprefetch_verify() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_mal_wc.rpl: Test validator with nodata, wildcards and ENT")
  void val_mal_wc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_negcache_ds.rpl: Test validator with negative cache DS response")
  void val_negcache_ds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  @DisplayName(
      "val_negcache_dssoa.rpl: Test validator with negative cache DS response with cached SOA")
  void val_negcache_dssoa() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("aggressive NSEC is not supported")
  @Test
  @DisplayName(
      "val_negcache_nodata.rpl: Test validator with negative cache NXDOMAIN response (aggressive NSEC)")
  void val_negcache_nodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests unbound option domain-insecure, not available here")
  @Test
  @DisplayName("val_negcache_nta.rpl: Test to not do aggressive NSEC for domains under NTA")
  void val_negcache_nta() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("aggressive NSEC is not supported")
  @Test
  @DisplayName(
      "val_negcache_nxdomain.rpl: Test validator with negative cache NXDOMAIN response (aggressive NSEC)")
  void val_negcache_nxdomain() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("irrelevant - if we wouldn't want AD, we wouldn't be using this stuff")
  @Test
  @DisplayName("val_noadwhennodo.rpl: Test if AD bit is returned on non-DO query.")
  void val_noadwhennodo() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nodata.rpl: Test validator with nodata response")
  void val_nodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nodatawc.rpl: Test validator with wildcard nodata response")
  void val_nodatawc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nodatawc_badce.rpl: Test validator with wildcard nodata, bad closest encloser")
  void val_nodatawc_badce() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nodatawc_nodeny.rpl: Test validator with wildcard nodata response without qdenial")
  void val_nodatawc_nodeny() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nodatawc_one.rpl: Test validator with wildcard nodata response with one NSEC")
  void val_nodatawc_one() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nodatawc_wcns.rpl: Test validator with wildcard nodata response from parent zone with SOA")
  void val_nodatawc_wcns() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nodatawc_wrongdeleg.rpl: Test validator with wildcard nodata response from parent zone")
  void val_nodatawc_wrongdeleg() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nodata_ent.rpl: Test validator with nodata on empty nonterminal response")
  void val_nodata_ent() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nodata_entnx.rpl: Test validator with nodata on empty nonterminal response with rcode NXDOMAIN")
  void val_nodata_entnx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nodata_entwc.rpl: Test validator with wildcard nodata on empty nonterminal response")
  void val_nodata_entwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nodata_failsig.rpl: Test validator with nodata response with bogus RRSIG")
  void val_nodata_failsig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nodata_failwc.rpl: Test validator with nodata response with wildcard expanded NSEC record, original NSEC owner does not provide proof for QNAME. CVE-2017-15105 test.")
  void val_nodata_failwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nodata_hasdata.rpl: Test validator with nodata response, that proves the data.")
  void val_nodata_hasdata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nodata_zonecut.rpl: Test validator with nodata response from wrong side of zonecut")
  void val_nodata_zonecut() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nokeyprime.rpl: Test validator with failed key prime, no keys.")
  void val_nokeyprime() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_b1_nameerror.rpl: Test validator NSEC3 B.1 name error.")
  void val_nsec3_b1_nameerror() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b1_nameerror_noce.rpl: Test validator NSEC3 B.1 name error without ce NSEC3.")
  void val_nsec3_b1_nameerror_noce() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b1_nameerror_nonc.rpl: Test validator NSEC3 B.1 name error without nc NSEC3.")
  void val_nsec3_b1_nameerror_nonc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b1_nameerror_nowc.rpl: Test validator NSEC3 B.1 name error without wc NSEC3.")
  void val_nsec3_b1_nameerror_nowc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_b21_nodataent.rpl: Test validator NSEC3 B.2.1 no data empty nonterminal.")
  void val_nsec3_b21_nodataent() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b21_nodataent_wr.rpl: Test validator NSEC3 B.2.1 no data empty nonterminal, wrong rr.")
  void val_nsec3_b21_nodataent_wr() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_b2_nodata.rpl: Test validator NSEC3 B.2 no data.")
  void val_nsec3_b2_nodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_b2_nodata_nons.rpl: Test validator NSEC3 B.2 no data, without NSEC3.")
  void val_nsec3_b2_nodata_nons() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b3_optout.rpl: Test validator NSEC3 B.3 referral to optout unsigned zone.")
  void val_nsec3_b3_optout() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  @DisplayName(
      "val_nsec3_b3_optout_negcache.rpl: Test validator NSEC3 B.3 referral optout with negative cache.")
  void val_nsec3_b3_optout_negcache() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b3_optout_noce.rpl: Test validator NSEC3 B.3 optout unsigned, without ce.")
  void val_nsec3_b3_optout_noce() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b3_optout_nonc.rpl: Test validator NSEC3 B.3 optout unsigned, without nc.")
  void val_nsec3_b3_optout_nonc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_b4_wild.rpl: Test validator NSEC3 B.4 wildcard expansion.")
  void val_nsec3_b4_wild() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b4_wild_wr.rpl: Test validator NSEC3 B.4 wildcard expansion, wrong NSEC3.")
  void val_nsec3_b4_wild_wr() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_b5_wcnodata.rpl: Test validator NSEC3 B.5 wildcard nodata.")
  void val_nsec3_b5_wcnodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b5_wcnodata_noce.rpl: Test validator NSEC3 B.5 wildcard nodata, without ce.")
  void val_nsec3_b5_wcnodata_noce() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b5_wcnodata_nonc.rpl: Test validator NSEC3 B.5 wildcard nodata, without nc.")
  void val_nsec3_b5_wcnodata_nonc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_b5_wcnodata_nowc.rpl: Test validator NSEC3 B.5 wildcard nodata, without wc.")
  void val_nsec3_b5_wcnodata_nowc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_cnametocnamewctoposwc.rpl: Test validator with a regular cname to wildcard cname to wildcard response")
  void val_nsec3_cnametocnamewctoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_cname_ds.rpl: Test validator with NSEC3 CNAME for qtype DS.")
  void val_nsec3_cname_ds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_cname_par.rpl: Test validator with NSEC3 wildcard CNAME to parent.")
  void val_nsec3_cname_par() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_cname_sub.rpl: Test validator with NSEC3 wildcard CNAME to subzone.")
  void val_nsec3_cname_sub() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_entnodata_optout.rpl: Test validator with NSEC3 response for NODATA ENT with optout.")
  void val_nsec3_entnodata_optout() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_entnodata_optout_badopt.rpl: Test validator with NSEC3 response for NODATA ENT with optout.")
  void val_nsec3_entnodata_optout_badopt() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_entnodata_optout_match.rpl: Test validator NODATA ENT with nsec3 optout matches the ent.")
  void val_nsec3_entnodata_optout_match() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_iter_high.rpl: Test validator with nxdomain NSEC3 with too high iterations")
  void val_nsec3_iter_high() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_nodatawccname.rpl: Test validator with nodata NSEC3 abused wildcarded CNAME.")
  void val_nsec3_nodatawccname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_nods.rpl: Test validator with NSEC3 with no DS referral.")
  void val_nsec3_nods() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_nods_badopt.rpl: Test validator with NSEC3 with no DS with wrong optout bit.")
  void val_nsec3_nods_badopt() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_nods_badsig.rpl: Test validator with NSEC3 with no DS referral with bad signature.")
  void val_nsec3_nods_badsig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  @DisplayName(
      "val_nsec3_nods_negcache.rpl: Test validator with NSEC3 with no DS referral from neg cache.")
  void val_nsec3_nods_negcache() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_nods_soa.rpl: Test validator with NSEC3 with no DS referral abuse of apex.")
  void val_nsec3_nods_soa() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_optout_ad.rpl: Test validator with optout NSEC3 response that gets no AD.")
  void val_nsec3_optout_ad() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("more cache stuff")
  @Test
  @DisplayName(
      "val_nsec3_optout_cache.rpl: Test validator with NSEC3 span change and cache effects.")
  void val_nsec3_optout_cache() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nsec3_wcany.rpl: Test validator with NSEC3 wildcard qtype ANY response.")
  void val_nsec3_wcany() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nsec3_wcany_nodeny.rpl: Test validator with NSEC3 wildcard qtype ANY without denial.")
  void val_nsec3_wcany_nodeny() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nx.rpl: Test validator with nxdomain response")
  void val_nx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nx_failwc.rpl: Test validator with nxdomain response with wildcard expanded NSEC record, original NSEC owner does not provide proof for QNAME. CVE-2017-15105 test.")
  void val_nx_failwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nx_nodeny.rpl: Test validator with nxdomain response missing qname denial")
  void val_nx_nodeny() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nx_nowc.rpl: Test validator with nxdomain response missing wildcard denial")
  void val_nx_nowc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nx_nsec3_collision.rpl: Test validator with nxdomain NSEC3 with a collision.")
  void val_nx_nsec3_collision() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nx_nsec3_collision2.rpl: Test validator with nxdomain NSEC3 with a salt mismatch.")
  void val_nx_nsec3_collision2() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nx_nsec3_collision3.rpl: Test validator with nxdomain NSEC3 with a collision.")
  void val_nx_nsec3_collision3() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nx_nsec3_collision4.rpl: Test validator with nxdomain NSEC3 with a collision.")
  void val_nx_nsec3_collision4() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nx_nsec3_hashalg.rpl: Test validator with unknown NSEC3 hash algorithm.")
  void val_nx_nsec3_hashalg() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_nx_nsec3_nsecmix.rpl: Test validator with NSEC3 responses that has an NSEC mixed in.")
  void val_nx_nsec3_nsecmix() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nx_nsec3_params.rpl: Test validator with nxdomain NSEC3 several parameters.")
  void val_nx_nsec3_params() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_nx_overreach.rpl: Test validator with overreaching NSEC record")
  void val_nx_overreach() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_positive.rpl: Test validator with positive response")
  void val_positive() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_positive_nosigs.rpl: Test validator with positive response, signatures removed.")
  void val_positive_nosigs() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_positive_wc.rpl: Test validator with positive wildcard response")
  void val_positive_wc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_positive_wc_nodeny.rpl: Test validator with positive wildcard without qname denial")
  void val_positive_wc_nodeny() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_pos_truncns.rpl: Test validator with badly truncated positive response")
  void val_pos_truncns() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_qds_badanc.rpl: Test validator with DS query and a bad anchor")
  void val_qds_badanc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_qds_oneanc.rpl: Test validator with DS query and one anchor")
  void val_qds_oneanc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_qds_twoanc.rpl: Test validator with DS query and two anchors")
  void val_qds_twoanc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("NSEC records missing for validation, tests caching stuff")
  @Test
  @DisplayName("val_referd.rpl: Test validator with cache referral")
  void val_referd() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  @DisplayName("val_referglue.rpl: Test validator with cache referral with unsigned glue")
  void val_referglue() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  @DisplayName("val_refer_unsignadd.rpl: Test validator with a referral with unsigned additional")
  void val_refer_unsignadd() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_rrsig.rpl: Test validator with qtype RRSIG response")
  void val_rrsig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_secds.rpl: Test validator with secure delegation")
  void val_secds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_secds_nosig.rpl: Test validator with no signatures after secure delegation")
  void val_secds_nosig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_spurious_ns.rpl: Test validator with spurious unsigned NS in auth section")
  void val_spurious_ns() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests unbound specific config (stub zones)")
  @Test
  @DisplayName("val_stubds.rpl: Test stub with DS query")
  void val_stubds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_stub_noroot.rpl: Test validation of stub zone without root prime.")
  void val_stub_noroot() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ta_algo_dnskey.rpl: Test validator with multiple algorithm trust anchor")
  void val_ta_algo_dnskey() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName(
      "val_ta_algo_dnskey_dp.rpl: Test validator with multiple algorithm trust anchor without harden")
  void val_ta_algo_dnskey_dp() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("TODO: passed before accidentally, message normalization now exposes this")
  @Test
  @DisplayName("val_ta_algo_missing.rpl: Test validator with multiple algorithm missing one")
  void val_ta_algo_missing() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_ta_algo_missing_dp.rpl: Test validator with multiple algorithm missing one")
  void val_ta_algo_missing_dp() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_twocname.rpl: Test validator with unsigned CNAME to signed CNAME to data")
  void val_twocname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_unalgo_anchor.rpl: Test validator with unsupported algorithm trust anchor")
  void val_unalgo_anchor() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_unalgo_dlv.rpl: Test validator with unknown algorithm DLV anchor")
  void val_unalgo_dlv() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_unalgo_ds.rpl: Test validator with unknown algorithm delegation")
  void val_unalgo_ds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_unsecds.rpl: Test validator with insecure delegation")
  void val_unsecds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  @DisplayName(
      "val_unsecds_negcache.rpl: Test validator with insecure delegation and DS negative cache")
  void val_unsecds_negcache() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests the iterative resolver")
  @Test
  @DisplayName("val_unsecds_qtypeds.rpl: Test validator with insecure delegation and qtype DS.")
  void val_unsecds_qtypeds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_unsec_cname.rpl: Test validator with DS, unsec, cname sequence.")
  void val_unsec_cname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  @DisplayName("val_wild_pos.rpl: Test validator with direct wildcard positive response")
  void val_wild_pos() throws ParseException, IOException {
    runUnboundTest();
  }
}
