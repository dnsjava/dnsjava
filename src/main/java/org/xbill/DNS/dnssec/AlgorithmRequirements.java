// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Ingo Bauersachs
// Copyright (c) 2007-2024 NLnet Labs
package org.xbill.DNS.dnssec;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;

/** Storage for DNSKEY algorithm requirements. */
class AlgorithmRequirements {
  private static final int MAX_ALGORITHMS = 0xFF;
  private final ValUtils valUtils;

  public AlgorithmRequirements(ValUtils valUtils) {
    this.valUtils = valUtils;
  }

  /**
   * the algorithms (8-bit) with each a number.
   *
   * <p>0: not marked.<br>
   * 1: marked 'necessary but not yet fulfilled'<br>
   * 2: marked bogus.
   *
   * <p>Indexed by algorithm number.
   */
  private final short[] needs = new short[MAX_ALGORITHMS];

  /** The number of entries in {@link #needs} that are unfulfilled */
  @Getter private int num;

  /**
   * Initialize this instance from a signalled algo list.
   *
   * @param sigalg signalled algorithm list.
   */
  void initList(List<Integer> sigalg) {
    num = 0;
    for (Integer algo : sigalg) {
      needs[algo] = 1;
      num++;
    }
  }

  /**
   * Initialize algo needs structure, set algos from rrset as needed.
   *
   * @param dsRRset algorithms from this RRset are necessary.
   * @param favoriteDsAlgorithm filter to use only this DS algo.
   * @return List of signalled algorithms.
   */
  List<Integer> initDs(RRset dsRRset, int favoriteDsAlgorithm) {
    List<Integer> sigalg = new ArrayList<>();
    num = 0;
    for (Record r : dsRRset.rrs(false)) {
      DSRecord ds = (DSRecord) r;
      if (ds.getDigestID() != favoriteDsAlgorithm) {
        continue;
      }

      int algo = ds.getAlgorithm();
      if (!valUtils.isAlgorithmSupported(algo)) {
        continue;
      }

      if (needs[algo] == 0) {
        needs[algo] = 1;
        sigalg.add(algo);
        num++;
      }
    }

    return sigalg;
  }

  /**
   * Mark this algorithm as a success ({@link SecurityStatus#SECURE}), and see if we are done.
   *
   * @param algo: the algorithm processed to be secure.
   * @return if true, processing has finished successfully, we are satisfied.
   */
  boolean setSecure(int algo) {
    if (needs[algo] != 0) {
      needs[algo] = 0;
      num--;
      // done!
      return num == 0;
    }

    return false;
  }

  /**
   * Mark this algorithm a failure ({@link SecurityStatus#BOGUS}). It can later be overridden by a
   * success for this algorithm (with a different signature).
   *
   * @param algo the algorithm processed to be bogus.
   */
  void setBogus(int algo) {
    if (needs[algo] != 0) {
      // need it, but bogus
      needs[algo] = 2;
    }
  }

  /**
   * See how many algorithms are missing (not bogus or secure, but not processed)
   *
   * @return number of algorithms missing after processing.
   */
  int missing() {
    int miss = -1;
    // check if a needed algo was bogus - report that;
    // check the first missing algo - report that;
    // or return 0
    for (int i = 0; i < needs.length; i++) {
      if (needs[i] == 2) {
        return 0;
      }

      if (needs[i] == 1 && miss == -1) {
        miss = i;
      }
    }

    if (miss != -1) {
      return miss;
    }

    return 0;
  }
}
