// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import static org.xbill.DNS.SetResponseType.CNAME;
import static org.xbill.DNS.SetResponseType.DELEGATION;
import static org.xbill.DNS.SetResponseType.DNAME;
import static org.xbill.DNS.SetResponseType.NXDOMAIN;
import static org.xbill.DNS.SetResponseType.NXRRSET;
import static org.xbill.DNS.SetResponseType.SUCCESSFUL;
import static org.xbill.DNS.SetResponseType.UNKNOWN;

import java.util.ArrayList;
import java.util.List;
import lombok.Getter;

/**
 * The Response from a query to {@link Cache#lookupRecords(Name, int, int)} or {@link
 * Zone#findRecords(Name, int)}.
 *
 * @see Cache
 * @see Zone
 * @author Brian Wellington
 */
public class SetResponse {
  private static final SetResponse SR_UNKNOWN = new SetResponse(UNKNOWN, null, false);
  private static final SetResponse SR_UNKNOWN_AUTH = new SetResponse(UNKNOWN, null, true);
  private static final SetResponse SR_NXDOMAIN = new SetResponse(NXDOMAIN, null, false);
  private static final SetResponse SR_NXDOMAIN_AUTH = new SetResponse(NXDOMAIN, null, true);
  private static final SetResponse SR_NXRRSET = new SetResponse(NXRRSET, null, false);
  private static final SetResponse SR_NXRRSET_AUTH = new SetResponse(NXRRSET, null, true);

  private final SetResponseType type;

  /**
   * @since 3.6
   */
  @Getter private boolean isAuthenticated;

  private List<RRset> data;

  private SetResponse(SetResponseType type, RRset rrset, boolean isAuthenticated) {
    this.type = type;
    this.isAuthenticated = isAuthenticated;
    if (rrset != null) {
      addRRset(rrset);
    }
  }

  static SetResponse ofType(SetResponseType type) {
    return ofType(type, null, false);
  }

  static SetResponse ofType(SetResponseType type, RRset rrset) {
    return ofType(type, rrset, false);
  }

  static SetResponse ofType(SetResponseType type, RRset rrset, boolean isAuthenticated) {
    switch (type) {
      case UNKNOWN:
        return isAuthenticated ? SR_UNKNOWN_AUTH : SR_UNKNOWN;
      case NXDOMAIN:
        return isAuthenticated ? SR_NXDOMAIN_AUTH : SR_NXDOMAIN;
      case NXRRSET:
        return isAuthenticated ? SR_NXRRSET_AUTH : SR_NXRRSET;
      case DELEGATION:
      case CNAME:
      case DNAME:
      case SUCCESSFUL:
        return new SetResponse(type, rrset, isAuthenticated);
      default:
        throw new IllegalArgumentException("invalid type");
    }
  }

  void addRRset(RRset rrset) {
    if (type.isSealed()) {
      throw new IllegalStateException("Attempted to add RRset to sealed response of type " + type);
    }

    if (data == null) {
      data = new ArrayList<>();
    }

    data.add(rrset);
  }

  /** Is the answer to the query unknown? */
  public boolean isUnknown() {
    return type == UNKNOWN;
  }

  /** Is the answer to the query that the name does not exist? */
  public boolean isNXDOMAIN() {
    return type == NXDOMAIN;
  }

  /** Is the answer to the query that the name exists, but the type does not? */
  public boolean isNXRRSET() {
    return type == NXRRSET;
  }

  /** Is the result of the lookup that the name is below a delegation? */
  public boolean isDelegation() {
    return type == DELEGATION;
  }

  /** Is the result of the lookup a CNAME? */
  public boolean isCNAME() {
    return type == CNAME;
  }

  /** Is the result of the lookup a DNAME? */
  public boolean isDNAME() {
    return type == DNAME;
  }

  /** Was the query successful? */
  public boolean isSuccessful() {
    return type == SUCCESSFUL;
  }

  /** If the query was successful, return the answers */
  public List<RRset> answers() {
    if (type != SUCCESSFUL) {
      return null;
    }
    return data;
  }

  /** If the query encountered a CNAME, return it. */
  public CNAMERecord getCNAME() {
    return (CNAMERecord) data.get(0).first();
  }

  /** If the query encountered a DNAME, return it. */
  public DNAMERecord getDNAME() {
    return (DNAMERecord) data.get(0).first();
  }

  /** If the query hit a delegation point, return the NS set. */
  public RRset getNS() {
    return data != null ? data.get(0) : null;
  }

  /** Prints the value of the SetResponse */
  @Override
  public String toString() {
    return type + (type.isPrintRecords() ? ": " + data.get(0) : "");
  }
}
