// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.ArrayList;
import java.util.List;

/**
 * The Response from a query to {@link Cache#lookupRecords(Name, int, int)} or {@link
 * Zone#findRecords(Name, int)}.
 *
 * @see Cache
 * @see Zone
 * @author Brian Wellington
 */
public class SetResponse {

  /** The Cache contains no information about the requested name/type */
  static final int UNKNOWN = 0;

  /**
   * The Zone does not contain the requested name, or the Cache has determined that the name does
   * not exist.
   */
  static final int NXDOMAIN = 1;

  /**
   * The Zone contains the name, but no data of the requested type, or the Cache has determined that
   * the name exists and has no data of the requested type.
   */
  static final int NXRRSET = 2;

  /** A delegation enclosing the requested name was found. */
  static final int DELEGATION = 3;

  /**
   * The Cache/Zone found a CNAME when looking for the name.
   *
   * @see CNAMERecord
   */
  static final int CNAME = 4;

  /**
   * The Cache/Zone found a DNAME when looking for the name.
   *
   * @see DNAMERecord
   */
  static final int DNAME = 5;

  /** The Cache/Zone has successfully answered the question for the requested name/type/class. */
  static final int SUCCESSFUL = 6;

  private static final SetResponse unknown = new SetResponse(UNKNOWN);
  private static final SetResponse nxdomain = new SetResponse(NXDOMAIN);
  private static final SetResponse nxrrset = new SetResponse(NXRRSET);

  private int type;
  private List<RRset> data;

  private SetResponse() {}

  SetResponse(int type, RRset rrset) {
    if (type < 0 || type > 6) {
      throw new IllegalArgumentException("invalid type");
    }
    this.type = type;
    this.data = new ArrayList<>();
    this.data.add(rrset);
  }

  SetResponse(int type) {
    if (type < 0 || type > 6) {
      throw new IllegalArgumentException("invalid type");
    }
    this.type = type;
    this.data = null;
  }

  static SetResponse ofType(int type) {
    switch (type) {
      case UNKNOWN:
        return unknown;
      case NXDOMAIN:
        return nxdomain;
      case NXRRSET:
        return nxrrset;
      case DELEGATION:
      case CNAME:
      case DNAME:
      case SUCCESSFUL:
        SetResponse sr = new SetResponse();
        sr.type = type;
        sr.data = null;
        return sr;
      default:
        throw new IllegalArgumentException("invalid type");
    }
  }

  void addRRset(RRset rrset) {
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
    return (data != null) ? data.get(0) : null;
  }

  /** Prints the value of the SetResponse */
  @Override
  public String toString() {
    switch (type) {
      case UNKNOWN:
        return "unknown";
      case NXDOMAIN:
        return "NXDOMAIN";
      case NXRRSET:
        return "NXRRSET";
      case DELEGATION:
        return "delegation: " + data.get(0);
      case CNAME:
        return "CNAME: " + data.get(0);
      case DNAME:
        return "DNAME: " + data.get(0);
      case SUCCESSFUL:
        return "successful";
      default:
        throw new IllegalStateException();
    }
  }
}
