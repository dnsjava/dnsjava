// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs
package org.xbill.DNS.dnssec;

import java.util.Comparator;

/**
 * This class implements a basic comparator for byte arrays. It is primarily useful for comparing
 * RDATA portions of DNS records in doing DNSSEC canonical ordering.
 *
 * @since 3.5
 */
final class ByteArrayComparator implements Comparator<Object> {
  private static final int MAX_BYTE = 0xFF;

  /** {@inheritDoc} */
  public int compare(Object o1, Object o2) {
    byte[] b1 = (byte[]) o1;
    byte[] b2 = (byte[]) o2;

    if (b1.length != b2.length) {
      return b1.length - b2.length;
    }

    for (int i = 0; i < b1.length; i++) {
      if (b1[i] != b2[i]) {
        return (b1[i] & MAX_BYTE) - (b2[i] & MAX_BYTE);
      }
    }

    return 0;
  }
}
