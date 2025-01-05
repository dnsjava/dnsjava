// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.Name;
import org.xbill.DNS.utils.base32;

/**
 * Cache for NSEC3 hashes and to keep track of the number of hash calculations as well as
 * calculation errors.
 */
class Nsec3ValidationState {
  private static final base32 b32 = new base32(base32.Alphabet.BASE32HEX, false, false);

  private final Map<String, Nsec3CacheEntry> cache = new HashMap<>();

  int numCalc;
  int numCalcErrors;

  public Nsec3CacheEntry computeIfAbsent(NSEC3Record nsec3, Name name)
      throws NoSuchAlgorithmException {
    String key = key(nsec3, name);
    Nsec3CacheEntry entry = cache.get(key);
    if (entry == null) {
      byte[] hash = nsec3.hashName(name);
      entry = new Nsec3CacheEntry(hash);
      cache.put(key, entry);
      numCalc++;
    }

    return entry;
  }

  @RequiredArgsConstructor
  static class Nsec3CacheEntry {
    @Getter private final byte[] hash;
    private String asBase32;

    String getHashAsBase32() {
      if (asBase32 == null) {
        asBase32 = b32.toString(hash);
      }

      return asBase32;
    }
  }

  private String key(NSEC3Record nsec3, Name name) {
    return name
        + "/"
        + nsec3.getHashAlgorithm()
        + "/"
        + nsec3.getIterations()
        + "/"
        + (nsec3.getSalt() == null ? "-" : new BigInteger(nsec3.getSalt()).toString());
  }
}
