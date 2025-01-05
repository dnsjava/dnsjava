// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;

/**
 * LookupResult instances holds the result of a successful lookup operation.
 *
 * @since 3.4
 */
@Data
public final class LookupResult {
  /** An unmodifiable list of records that this instance wraps, may not be null but can be empty */
  private final List<Record> records;

  /**
   * In the case of CNAME or DNAME indirection, this property contains the original name as well as
   * any intermediate redirect targets except the last one. For example, if X is a CNAME pointing to
   * Y which is a CNAME pointing to Z which has an A record, aliases will hold X and Y after
   * successful lookup.
   */
  private final List<Name> aliases;

  /** The queries and responses that made up the result. */
  @Getter(AccessLevel.PACKAGE)
  private final Map<Record, Message> queryResponsePairs;

  /**
   * Gets an indication if the message(s) that provided this result were authenticated, e.g. by
   * using {@link org.xbill.DNS.dnssec.ValidatingResolver} or when the upstream resolver has set the
   * {@link org.xbill.DNS.Flags#AD} flag.
   *
   * <p><b>IMPORTANT</b>: Note that in the latter case, the flag cannot be trusted unless the {@link
   * org.xbill.DNS.Resolver} used by the {@link LookupSession} that created this result:
   *
   * <ul>
   *   <li>has TSIG enabled
   *   <li>uses an externally secured transport, e.g. with IPSec or DNS over TLS.
   * </ul>
   */
  @Getter(AccessLevel.PACKAGE)
  private final boolean isAuthenticated;

  /**
   * Construct an instance with the provided records and, in the case of a CNAME or DNAME
   * indirection a List of aliases.
   *
   * @param records a list of records to return.
   * @param aliases a list of aliases discovered during lookup, or null if there was no indirection.
   * @deprecated This class is not intended for public instantiation.
   */
  @Deprecated
  public LookupResult(List<Record> records, List<Name> aliases) {
    this.records = Collections.unmodifiableList(new ArrayList<>(records));
    this.aliases =
        aliases == null
            ? Collections.emptyList()
            : Collections.unmodifiableList(new ArrayList<>(aliases));
    queryResponsePairs = Collections.emptyMap();
    isAuthenticated = false;
  }

  LookupResult(boolean isAuthenticated) {
    queryResponsePairs = Collections.emptyMap();
    this.isAuthenticated = isAuthenticated;
    records = Collections.emptyList();
    aliases = Collections.emptyList();
  }

  LookupResult(Record query, boolean isAuthenticated, Record result) {
    this.queryResponsePairs = Collections.singletonMap(query, null);
    this.isAuthenticated = isAuthenticated;
    this.records = Collections.singletonList(result);
    this.aliases = Collections.emptyList();
  }

  LookupResult(
      LookupResult previous,
      Record query,
      Message answer,
      boolean isAuthenticated,
      List<Record> records,
      List<Name> aliases) {
    Map<Record, Message> map = new HashMap<>(previous.queryResponsePairs.size() + 1);
    map.putAll(previous.queryResponsePairs);
    map.put(query, answer);
    this.queryResponsePairs = Collections.unmodifiableMap(map);
    this.isAuthenticated =
        previous.isAuthenticated
            && isAuthenticated
            && this.queryResponsePairs.values().stream()
                .filter(Objects::nonNull)
                .allMatch(a -> a.getHeader().getFlag(Flags.AD));
    this.records = Collections.unmodifiableList(new ArrayList<>(records));
    this.aliases = Collections.unmodifiableList(new ArrayList<>(aliases));
  }
}
