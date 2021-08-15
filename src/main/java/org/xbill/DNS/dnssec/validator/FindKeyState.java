// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs

package org.xbill.DNS.dnssec.validator;

import org.xbill.DNS.Name;
import org.xbill.DNS.dnssec.SRRset;

/**
 * State-object for the key-finding phase.
 *
 * @since 3.5
 */
class FindKeyState {
  /** The (initial) DS RRset for the following DNSKEY search and validate phase. */
  SRRset dsRRset;

  /** Iteratively holds the key during the search phase. */
  KeyEntry keyEntry;

  /**
   * The name of the key to search. This is taken from the RRSIG's signer name or the query name if
   * no signer name is available.
   */
  Name signerName;

  /** The query class of the key to find. */
  int qclass;

  /** Sets the key name being searched for when a DS response is provably not a delegation point. */
  Name emptyDSName;

  /** The initial key name when the key search is started from a trust anchor. */
  Name currentDSKeyName;
}
