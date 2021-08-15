// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs
package org.xbill.DNS.dnssec.validator;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;
import org.xbill.DNS.dnssec.SRRset;
import org.xbill.DNS.dnssec.SecurityStatus;

/**
 * A class for performing basic DNSSEC verification. The DNSJAVA package contains a similar class.
 * This is a reimplementation that allows us to have finer control over the validation process.
 *
 * @since 3.5
 */
@Slf4j
class DnsSecVerifier {
  /**
   * Find the matching DNSKEY(s) to an RRSIG within a DNSKEY rrset. Normally this will only return
   * one DNSKEY. It can return more than one, since KeyID/Footprints are not guaranteed to be
   * unique.
   *
   * @param dnskeyRrset The DNSKEY rrset to search.
   * @param signature The RRSIG to match against.
   * @return A List that contains one or more DNSKEYRecord objects; empty if a matching DNSKEY could
   *     not be found.
   */
  private List<DNSKEYRecord> findKey(RRset dnskeyRrset, RRSIGRecord signature) {
    if (!signature.getSigner().equals(dnskeyRrset.getName())) {
      log.trace(
          "could not find appropriate key because incorrect keyset was supplied. Wanted: {}, got: {}",
          signature.getSigner(),
          dnskeyRrset.getName());
      return Collections.emptyList();
    }

    int keyid = signature.getFootprint();
    int alg = signature.getAlgorithm();
    List<DNSKEYRecord> res = new ArrayList<>(dnskeyRrset.size());
    for (Record r : dnskeyRrset.rrs()) {
      DNSKEYRecord dnskey = (DNSKEYRecord) r;
      if (dnskey.getAlgorithm() == alg && dnskey.getFootprint() == keyid) {
        res.add(dnskey);
      }
    }

    return res;
  }

  /**
   * Verify an RRset against a particular signature.
   *
   * @param rrset The RRset to verify.
   * @param sigrec The signature record that signs the RRset.
   * @param keyRrset The keys used to create the signature record.
   * @param date The date against which to verify the signature.
   * @return {@link SecurityStatus#SECURE} if the signature verified, {@link SecurityStatus#BOGUS}
   *     if it did not verify (for any reason), and {@link SecurityStatus#UNCHECKED} if verification
   *     could not be completed (usually because the public key was not available).
   */
  private SecurityStatus verifySignature(
      SRRset rrset, RRSIGRecord sigrec, RRset keyRrset, Instant date) {
    List<DNSKEYRecord> keys = this.findKey(keyRrset, sigrec);
    if (keys.isEmpty()) {
      log.trace("could not find appropriate key");
      return SecurityStatus.BOGUS;
    }

    SecurityStatus status = SecurityStatus.UNCHECKED;
    for (DNSKEYRecord key : keys) {
      try {
        if (!rrset.getName().subdomain(keyRrset.getName())) {
          log.debug("signer name is off-tree");
          status = SecurityStatus.BOGUS;
          continue;
        }

        DNSSEC.verify(rrset, sigrec, key, date);
        ValUtils.setCanonicalNsecOwner(rrset, sigrec);
        return SecurityStatus.SECURE;
      } catch (DNSSECException e) {
        log.error(
            "Failed to validate RRset {}/{}", rrset.getName(), Type.string(rrset.getType()), e);
        status = SecurityStatus.BOGUS;
      }
    }

    return status;
  }

  /**
   * Verifies an RRset. This routine does not modify the RRset. This RRset is presumed to be
   * verifiable, and the correct DNSKEY rrset is presumed to have been found.
   *
   * @param rrset The RRset to verify.
   * @param keyRrset The keys to verify the signatures in the RRset to check.
   * @param date The date against which to verify the rrset.
   * @return SecurityStatus.SECURE if the rrest verified positively, SecurityStatus.BOGUS otherwise.
   */
  public SecurityStatus verify(SRRset rrset, RRset keyRrset, Instant date) {
    List<RRSIGRecord> sigs = rrset.sigs();
    if (sigs.isEmpty()) {
      log.info("RRset failed to verify due to lack of signatures");
      return SecurityStatus.BOGUS;
    }

    for (RRSIGRecord sigrec : sigs) {
      SecurityStatus res = this.verifySignature(rrset, sigrec, keyRrset, date);
      if (res == SecurityStatus.SECURE) {
        return res;
      }
    }

    log.info("RRset failed to verify: all signatures were BOGUS");
    return SecurityStatus.BOGUS;
  }

  /**
   * Verify an RRset against a single DNSKEY. Use this when you must be certain that an RRset signed
   * and verifies with a particular DNSKEY (as opposed to a particular DNSKEY rrset).
   *
   * @param rrset The rrset to verify.
   * @param dnskey The DNSKEY to verify with.
   * @param date The date against which to verify the rrset.
   * @return SecurityStatus.SECURE if the rrset verified, BOGUS otherwise.
   */
  public SecurityStatus verify(RRset rrset, DNSKEYRecord dnskey, Instant date) {
    List<RRSIGRecord> sigs = rrset.sigs();
    if (sigs.isEmpty()) {
      log.info("RRset failed to verify due to lack of signatures");
      return SecurityStatus.BOGUS;
    }

    for (RRSIGRecord sigrec : sigs) {
      // Skip RRSIGs that do not match our given key's footprint.
      if (sigrec.getFootprint() != dnskey.getFootprint()) {
        continue;
      }

      try {
        DNSSEC.verify(rrset, sigrec, dnskey, date);
        return SecurityStatus.SECURE;
      } catch (DNSSECException e) {
        log.error("Failed to validate RRset", e);
      }
    }

    log.info("RRset failed to verify: all signatures were BOGUS");
    return SecurityStatus.BOGUS;
  }
}
