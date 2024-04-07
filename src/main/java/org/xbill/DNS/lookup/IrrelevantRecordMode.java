// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

/** Defines the handling of irrelevant records during messages normalization. */
enum IrrelevantRecordMode {
  /** Irrelevant records are removed from the message, but otherwise ignored. */
  REMOVE,
  /** Throws an error when an irrelevant record is found. */
  THROW,
}
