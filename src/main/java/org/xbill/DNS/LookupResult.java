package org.xbill.DNS;

import java.util.List;
import java.util.Objects;
import org.xbill.DNS.exceptions.AdditionalDetail;
import org.xbill.DNS.exceptions.LookupFailedException;

/** LookupResult instances holds the result of a successful lookup operation. */
public class LookupResult {
  private final List<Record> records;
  private final AdditionalDetail additionalDetail;

  /**
   * Construct an instance with the provided records.
   *
   * @param records a list of records to return, or null if there was no response
   * @param additionalDetail additional detail on this response, such as the reason for records
   *     being null.
   */
  public LookupResult(List<Record> records, AdditionalDetail additionalDetail) {
    this.records = records;
    this.additionalDetail = additionalDetail;
  }

  /**
   * An unmodifiable list of records that this instance wraps
   *
   * @return an unmodifiable List of Record instances.
   */
  public List<Record> get() throws LookupFailedException {
    return records;
  }

  public AdditionalDetail getAdditionalDetail() {
    return additionalDetail;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    LookupResult that = (LookupResult) o;
    return records.equals(that.records) && additionalDetail == that.additionalDetail;
  }

  @Override
  public int hashCode() {
    return Objects.hash(records, additionalDetail);
  }

  @Override
  public String toString() {
    return "LookupResult{" + "records=" + records + ", additionalDetail=" + additionalDetail + '}';
  }
}
