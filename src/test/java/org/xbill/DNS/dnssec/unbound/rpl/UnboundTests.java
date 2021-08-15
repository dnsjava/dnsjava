// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec.unbound.rpl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.io.File;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.CNAMERecord;
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
import org.xbill.DNS.dnssec.SRRset;
import org.xbill.DNS.dnssec.TestBase;
import org.xbill.DNS.dnssec.validator.ValUtils;

class UnboundTests extends TestBase {
  void runUnboundTest() throws ParseException, IOException {
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
      config.put(ValUtils.ALGORITHM_ENABLED + "." + DNSSEC.Algorithm.DSA, Boolean.TRUE.toString());
      config.put(
          ValUtils.ALGORITHM_ENABLED + "." + DNSSEC.Algorithm.DSA_NSEC3_SHA1,
          Boolean.TRUE.toString());
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
          ds.addRecord(Record.newRecord(s.getName(), s.getType(), s.getDClass()), Section.QUESTION);
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
      Message s = resolver.send(c.query);
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
      assertEquals(
          c.response.getHeader().getFlag(Flags.AD),
          s.getHeader().getFlag(Flags.AD),
          "AD Flag must match");
      assertEquals(
          Rcode.string(c.response.getRcode()), Rcode.string(s.getRcode()), "RCode must match");
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

  static void xmain(String[] xargs) {
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
            put("val_anchor_nx.rpl", "tests caching of NX from a parent resolver");
            put("val_anchor_nx_nosig.rpl", "tests caching of NX from a parent resolver");
            put("val_negcache_nta.rpl", "tests unbound option domain-insecure, not available here");
          }
        };

    for (String f : new File("./src/test/resources/unbound").list()) {
      String comment = ignored.get(f);
      if (comment != null) {
        System.out.println("    @Disabled(\"" + comment + "\")");
      }

      System.out.println("    @Test");
      System.out.println(
          "    void " + f.split("\\.")[0] + "() throws ParseException, IOException {");
      System.out.println("        runUnboundTest();");
      System.out.println("    }");
      System.out.println();
    }
  }

  @Test
  void val_adbit() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_adcopy() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests caching of NX from a parent resolver")
  @Test
  void val_anchor_nx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests caching of NX from a parent resolver")
  @Test
  void val_anchor_nx_nosig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ans_dsent() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ans_nx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_any() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_any_cname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_any_dname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnameinsectopos() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnamenx_dblnsec() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnamenx_rcodenx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnameqtype() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametocloser() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametocloser_nosig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametocnamewctoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametodname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametodnametocnametopos() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("incomplete CNAME answer")
  @Test
  void val_cnametoinsecure() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametonodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametonodata_nonsec() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("incomplete CNAME answer")
  @Test
  void val_cnametonsec() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametonx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("incomplete CNAME answer")
  @Test
  void val_cnametooptin() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametooptout() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametopos() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametoposnowc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnametoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnamewctonodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnamewctonx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cnamewctoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cname_loop1() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cname_loop2() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_cname_loop3() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_dnametoolong() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_dnametopos() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_dnametoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_dnamewc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  void val_dsnsec() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_afterprime() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_cname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_cnamesub() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_cnamesubbogus() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_gost() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_gost_downgrade() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_sha2() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_sha2_downgrade() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_sha2_downgrade_override() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ds_sha2_lenient() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_entds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_faildnskey() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests an unbound specific config option")
  @Test
  void val_faildnskey_ok() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("irrelevant, we're not a recursive resolver")
  @Test
  void val_fwdds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_keyprefetch() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_keyprefetch_verify() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_mal_wc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_negcache_ds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  void val_negcache_dssoa() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("aggressive NSEC is not supported")
  @Test
  void val_negcache_nodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests unbound option domain-insecure, not available here")
  @Test
  void val_negcache_nta() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("aggressive NSEC is not supported")
  @Test
  void val_negcache_nxdomain() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("irrelevant - if we wouldn't want AD, we wouldn't be using this stuff")
  @Test
  void val_noadwhennodo() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodatawc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodatawc_badce() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodatawc_nodeny() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodatawc_one() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodatawc_wcns() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodatawc_wrongdeleg() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodata_ent() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodata_entnx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodata_entwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodata_failsig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodata_failwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodata_hasdata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nodata_zonecut() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nokeyprime() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b1_nameerror() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b1_nameerror_noce() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b1_nameerror_nonc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b1_nameerror_nowc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b21_nodataent() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b21_nodataent_wr() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b2_nodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b2_nodata_nons() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b3_optout() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  void val_nsec3_b3_optout_negcache() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b3_optout_noce() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b3_optout_nonc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b4_wild() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b4_wild_wr() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b5_wcnodata() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b5_wcnodata_noce() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b5_wcnodata_nonc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_b5_wcnodata_nowc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_cnametocnamewctoposwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_cname_ds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_cname_par() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_cname_sub() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_entnodata_optout() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_entnodata_optout_badopt() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_entnodata_optout_match() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_iter_high() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_nodatawccname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_nods() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_nods_badopt() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_nods_badsig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  void val_nsec3_nods_negcache() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_nods_soa() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_optout_ad() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("more cache stuff")
  @Test
  void val_nsec3_optout_cache() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_wcany() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nsec3_wcany_nodeny() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_failwc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_nodeny() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_nowc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_nsec3_collision() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_nsec3_collision2() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_nsec3_collision3() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_nsec3_collision4() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_nsec3_hashalg() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_nsec3_nsecmix() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_nsec3_params() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_nx_overreach() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_positive() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_positive_nosigs() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_positive_wc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_positive_wc_nodeny() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_pos_truncns() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_qds_badanc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_qds_oneanc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_qds_twoanc() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("NSEC records missing for validation, tests caching stuff")
  @Test
  void val_referd() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  void val_referglue() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  void val_refer_unsignadd() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_rrsig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_secds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_secds_nosig() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests unbound specific config (stub zones)")
  @Test
  void val_stubds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_spurious_ns() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_stub_noroot() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ta_algo_dnskey() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ta_algo_dnskey_dp() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ta_algo_missing() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_ta_algo_missing_dp() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_twocname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_unalgo_anchor() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_unalgo_dlv() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_unalgo_ds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_unsecds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("we don't do negative caching")
  @Test
  void val_unsecds_negcache() throws ParseException, IOException {
    runUnboundTest();
  }

  @Disabled("tests the iterative resolver")
  @Test
  void val_unsecds_qtypeds() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_unsec_cname() throws ParseException, IOException {
    runUnboundTest();
  }

  @Test
  void val_wild_pos() throws ParseException, IOException {
    runUnboundTest();
  }
}
