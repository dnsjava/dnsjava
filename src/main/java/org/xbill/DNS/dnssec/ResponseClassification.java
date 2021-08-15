// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs
package org.xbill.DNS.dnssec;

/**
 * These are response subtypes. They are necessary for determining the validation strategy. They
 * have no bearing on the iterative resolution algorithm, so they are confined here.
 *
 * @since 3.5
 */
enum ResponseClassification {
  /** Not a recognized subtype. */
  UNKNOWN,

  /** A postive, direct, response. */
  POSITIVE,

  /** A postive response, with a CNAME/DNAME chain. */
  CNAME,

  /** A NOERROR/NODATA response. */
  NODATA,

  /** A NXDOMAIN response. */
  NAMEERROR,

  /** A response to a qtype=ANY query. */
  ANY,

  /** A response with CNAMES that points to a non-existing type. */
  CNAME_NODATA,

  /** A response with CNAMES that points into the void. */
  CNAME_NAMEERROR,

  /** A referral, from cache with a nonRD query. */
  REFERRAL,
}
