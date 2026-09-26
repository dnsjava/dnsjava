// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import lombok.experimental.UtilityClass;

/** Constants for common Hash/Digest lengths. */
@UtilityClass
class DigestLengths {
  static final int MD5 = 16;
  static final int SHA1 = 20;
  static final int SHA224 = 28;
  static final int SHA256 = 32;
  static final int SHA384 = 48;
  static final int SHA512 = 64;
  static final int GOST3411 = 32;
  static final int GOST3411_12 = 64;
  static final int SM3 = 32;
}
