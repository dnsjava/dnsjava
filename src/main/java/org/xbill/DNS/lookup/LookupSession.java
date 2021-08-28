// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;
import lombok.Builder;
import lombok.NonNull;
import lombok.Singular;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Cache;
import org.xbill.DNS.Credibility;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SetResponse;
import org.xbill.DNS.Type;
import org.xbill.DNS.hosts.HostsFileParser;

/**
 * LookupSession provides facilities to make DNS Queries. A LookupSession is intended to be long
 * lived, and it's behaviour can be configured using the properties of the {@link
 * LookupSessionBuilder} instance returned by {@link #builder()}.
 */
@Slf4j
public class LookupSession {
  public static final int DEFAULT_MAX_ITERATIONS = 16;
  public static final int DEFAULT_NDOTS = 1;

  private final Resolver resolver;
  private final int maxRedirects;
  private final int ndots;
  private final List<Name> searchPath;
  private final boolean cycleResults;
  private final Map<Integer, Cache> caches;
  private final HostsFileParser hostsFileParser;

  /**
   * @param resolver The {@link Resolver} to use to look up records.
   * @param maxRedirects The maximum number of CNAME or DNAME redirects allowed before lookups will
   *     fail with {@link RedirectOverflowException}. Defaults to {@value
   *     org.xbill.DNS.lookup.LookupSession#DEFAULT_MAX_ITERATIONS}.
   * @param ndots The threshold for the number of dots which must appear in a name before it is
   *     considered absolute. The default is {@value
   *     org.xbill.DNS.lookup.LookupSession#DEFAULT_NDOTS}, meaning that if there are any dots in a
   *     name, the name will be tried first as an absolute name.
   * @param searchPath Configures the search path used to look up relative names with less than
   *     ndots dots.
   * @param cycleResults If set to {@code true}, cached results with multiple records will be
   *     returned with the starting point shifted one step per request.
   * @param caches Enable caching using the supplied caches.
   * @param hostsFileParser Configures the local hosts database file parser to use within this
   *     session.
   */
  @Builder
  private LookupSession(
      @NonNull Resolver resolver,
      int maxRedirects,
      int ndots,
      @Singular("searchPath") List<Name> searchPath,
      boolean cycleResults,
      List<Cache> caches,
      HostsFileParser hostsFileParser) {
    this.resolver = resolver;
    this.maxRedirects = maxRedirects;
    this.ndots = ndots;
    this.searchPath = searchPath;
    this.cycleResults = cycleResults;
    this.caches = caches.stream().collect(Collectors.toMap(Cache::getDClass, e -> e));
    this.hostsFileParser = hostsFileParser;
  }

  /**
   * A builder for {@link LookupSession} instances. An instance of this class is obtained by calling
   * {@link LookupSession#builder()} and configured using the methods with names corresponding to
   * the different properties. Once fully configured, a {@link LookupSession} instance is obtained
   * by calling {@link LookupSessionBuilder#build()} on the builder instance.
   */
  public static class LookupSessionBuilder {
    /**
     * Enable querying the local hosts database using the system defaults.
     *
     * @see HostsFileParser
     */
    public LookupSessionBuilder defaultHostsFileParser() {
      hostsFileParser = new HostsFileParser();
      return this;
    }

    /**
     * Enable caching using the supplied cache. An existing {@link Cache} for the same class will be
     * replaced.
     *
     * @see Cache
     */
    public LookupSessionBuilder cache(@NonNull Cache cache) {
      if (caches == null) {
        caches = new ArrayList<>(1);
      }
      for (Cache c : caches) {
        if (c.getDClass() == cache.getDClass()) {
          caches.remove(c);
          break;
        }
      }
      caches.add(cache);
      return this;
    }

    /**
     * Enable caching using the supplied caches. Existing {@link Cache}s for the same class will be
     * replaced.
     *
     * @see Cache
     */
    public LookupSessionBuilder caches(@NonNull Collection<Cache> caches) {
      caches.forEach(this::cache);
      return this;
    }

    /** Disables using a cache for lookups. */
    public LookupSessionBuilder clearCaches() {
      caches.clear();
      return this;
    }

    /**
     * Enable caching using the supplied cache for the given class.
     *
     * @param dclass unused
     * @deprecated use {@link #cache(Cache)}, the {@link Cache} already provides the class.
     * @see Cache
     */
    @Deprecated
    public LookupSessionBuilder cache(@NonNull Integer dclass, @NonNull Cache cache) {
      cache(cache);
      return this;
    }

    /**
     * Enable caching using the supplied caches.
     *
     * @param caches unused
     * @deprecated use {@link #cache(Cache)} or {@link #caches(Collection)}, the {@link Cache}
     *     already provides the class.
     * @see Cache
     */
    @Deprecated
    public LookupSessionBuilder caches(@NonNull Map<Integer, Cache> caches) {
      return caches(caches.values());
    }

    void preBuild() {
      // note that this transform is idempotent, as concatenating an already absolute Name with root
      // is a noop.
      if (searchPath != null) {
        this.searchPath =
            searchPath.stream()
                .map(
                    name -> {
                      try {
                        return Name.concatenate(name, Name.root);
                      } catch (NameTooLongException e) {
                        throw new IllegalArgumentException("Search path name too long");
                      }
                    })
                .collect(Collectors.toCollection(ArrayList::new));
      }
    }
  }

  /** Returns a new {@link LookupSessionBuilder} instance. */
  public static LookupSessionBuilder builder() {
    LookupSessionBuilder builder =
        new LookupSessionBuilder() {
          @Override
          public LookupSession build() {
            preBuild();
            return super.build();
          }
        };
    builder.maxRedirects = DEFAULT_MAX_ITERATIONS;
    builder.ndots = DEFAULT_NDOTS;
    builder.cache(new Cache(DClass.IN));
    return builder;
  }

  /**
   * Make an asynchronous lookup of the provided name using the default {@link DClass#IN}.
   *
   * @param name the name to look up.
   * @param type the type to look up, values should correspond to constants in {@link Type}.
   * @return A {@link CompletionStage} what will yield the eventual lookup result.
   */
  public CompletionStage<LookupResult> lookupAsync(Name name, int type) {
    return lookupAsync(name, type, DClass.IN);
  }

  /**
   * Make an asynchronous lookup of the provided name.
   *
   * @param name the name to look up.
   * @param type the type to look up, values should correspond to constants in {@link Type}.
   * @param dclass the class to look up, values should correspond to constants in {@link DClass}.
   * @return A {@link CompletionStage} what will yield the eventual lookup result.
   */
  public CompletionStage<LookupResult> lookupAsync(Name name, int type, int dclass) {
    List<Name> searchNames = expandName(name);
    LookupResult localHostsLookupResult = lookupWithHosts(searchNames, type);
    if (localHostsLookupResult != null) {
      return CompletableFuture.completedFuture(localHostsLookupResult);
    }

    return lookupUntilSuccess(searchNames.iterator(), type, dclass);
  }

  /**
   * Generate a stream of names according to the search path application semantics. The semantics of
   * this is a bit odd, but they are inherited from {@link Lookup}. Note that the stream returned is
   * never empty, as it will at the very least always contain {@code name}.
   */
  List<Name> expandName(Name name) {
    if (name.isAbsolute()) {
      return Collections.singletonList(name);
    }

    List<Name> fromSearchPath =
        searchPath.stream()
            .map(searchSuffix -> safeConcat(name, searchSuffix))
            .filter(Objects::nonNull)
            .collect(Collectors.toCollection(ArrayList::new));

    if (name.labels() > ndots) {
      fromSearchPath.add(0, safeConcat(name, Name.root));
    } else {
      fromSearchPath.add(safeConcat(name, Name.root));
    }

    return fromSearchPath;
  }

  private static Name safeConcat(Name name, Name suffix) {
    try {
      return Name.concatenate(name, suffix);
    } catch (NameTooLongException e) {
      return null;
    }
  }

  private LookupResult lookupWithHosts(List<Name> names, int type) {
    if (hostsFileParser != null && (type == Type.A || type == Type.AAAA)) {
      try {
        for (Name name : names) {
          Optional<InetAddress> result = hostsFileParser.getAddressForHost(name, type);
          if (result.isPresent()) {
            Record r;
            if (type == Type.A) {
              r = new ARecord(name, DClass.IN, 0, result.get());
            } else {
              r = new AAAARecord(name, DClass.IN, 0, result.get());
            }
            return new LookupResult(Collections.singletonList(r), Collections.emptyList());
          }
        }
      } catch (IOException e) {
        log.debug("Local hosts database parsing failed, ignoring and using resolver", e);
      }
    }

    return null;
  }

  private CompletionStage<LookupResult> lookupUntilSuccess(
      Iterator<Name> names, int type, int dclass) {

    Record query = Record.newRecord(names.next(), type, dclass);
    return lookupWithCache(query, null)
        .thenCompose(answer -> resolveRedirects(answer, query))
        .handle(
            (result, ex) -> {
              Throwable cause = ex == null ? null : ex.getCause();
              if (cause instanceof NoSuchDomainException || cause instanceof NoSuchRRSetException) {
                if (names.hasNext()) {
                  return lookupUntilSuccess(names, type, dclass);
                } else {
                  return completeExceptionally(cause);
                }
              } else if (cause != null) {
                return completeExceptionally(cause);
              } else {
                return CompletableFuture.completedFuture(result);
              }
            })
        .thenCompose(x -> x);
  }

  private CompletionStage<LookupResult> lookupWithCache(Record queryRecord, List<Name> aliases) {
    return Optional.ofNullable(caches.get(queryRecord.getDClass()))
        .map(c -> c.lookupRecords(queryRecord.getName(), queryRecord.getType(), Credibility.NORMAL))
        .map(setResponse -> setResponseToMessageFuture(setResponse, queryRecord, aliases))
        .orElseGet(() -> lookupWithResolver(queryRecord, aliases));
  }

  private CompletionStage<LookupResult> lookupWithResolver(Record queryRecord, List<Name> aliases) {
    return resolver
        .sendAsync(Message.newQuery(queryRecord))
        .thenApply(this::maybeAddToCache)
        .thenApply(answer -> buildResult(answer, aliases, queryRecord));
  }

  private Message maybeAddToCache(Message message) {
    for (RRset set : message.getSectionRRsets(Section.ANSWER)) {
      if ((set.getType() == Type.CNAME || set.getType() == Type.DNAME) && set.size() != 1) {
        throw new InvalidZoneDataException("Multiple CNAME RRs not allowed, see RFC1034 3.6.2");
      }
    }
    Optional.ofNullable(caches.get(message.getQuestion().getDClass()))
        .ifPresent(cache -> cache.addMessage(message));
    return message;
  }

  private CompletionStage<LookupResult> setResponseToMessageFuture(
      SetResponse setResponse, Record queryRecord, List<Name> aliases) {
    if (setResponse.isNXDOMAIN()) {
      return completeExceptionally(
          new NoSuchDomainException(queryRecord.getName(), queryRecord.getType()));
    }
    if (setResponse.isNXRRSET()) {
      return completeExceptionally(
          new NoSuchRRSetException(queryRecord.getName(), queryRecord.getType()));
    }
    if (setResponse.isSuccessful()) {
      List<Record> records =
          setResponse.answers().stream()
              .flatMap(rrset -> rrset.rrs(cycleResults).stream())
              .collect(Collectors.toList());
      return CompletableFuture.completedFuture(new LookupResult(records, aliases));
    }
    return null;
  }

  private <T extends Throwable> CompletionStage<LookupResult> completeExceptionally(T failure) {
    CompletableFuture<LookupResult> future = new CompletableFuture<>();
    future.completeExceptionally(failure);
    return future;
  }

  private CompletionStage<LookupResult> resolveRedirects(LookupResult response, Record query) {
    return maybeFollowRedirect(response, query, 1);
  }

  private CompletionStage<LookupResult> maybeFollowRedirect(
      LookupResult response, Record query, int redirectCount) {
    if (redirectCount > maxRedirects) {
      throw new RedirectOverflowException(maxRedirects);
    }

    List<Record> records = response.getRecords();
    if (!records.isEmpty()
        && (records.get(0).getType() == Type.CNAME || records.get(0).getType() == Type.DNAME)) {
      return maybeFollowRedirectsInAnswer(response, query, redirectCount);
    } else {
      return CompletableFuture.completedFuture(response);
    }
  }

  private CompletionStage<LookupResult> maybeFollowRedirectsInAnswer(
      LookupResult response, Record query, int redirectCount) {
    List<Name> aliases = new ArrayList<>(response.getAliases());
    List<Record> results = new ArrayList<>();
    Name current = query.getName();
    for (Record r : response.getRecords()) {
      if (redirectCount > maxRedirects) {
        throw new RedirectOverflowException(maxRedirects);
      }

      if (r.getDClass() != query.getDClass()) {
        continue;
      }

      if (r.getType() == Type.CNAME && current.equals(r.getName())) {
        aliases.add(current);
        redirectCount++;
        current = ((CNAMERecord) r).getTarget();
      } else if (r.getType() == Type.DNAME && current.subdomain(r.getName())) {
        aliases.add(current);
        redirectCount++;
        try {
          current = current.fromDNAME((DNAMERecord) r);
        } catch (NameTooLongException e) {
          throw new InvalidZoneDataException(
              "Cannot derive DNAME from " + r + " for " + current, e);
        }
      } else if (r.getType() == query.getType() && current.equals(r.getName())) {
        results.add(r);
      }
    }

    if (!results.isEmpty()) {
      return CompletableFuture.completedFuture(new LookupResult(results, aliases));
    }

    if (redirectCount > maxRedirects) {
      throw new RedirectOverflowException(maxRedirects);
    }

    int finalRedirectCount = redirectCount + 1;
    Record redirectQuery = Record.newRecord(current, query.getType(), query.getDClass());
    return lookupWithCache(redirectQuery, aliases)
        .thenCompose(
            responseFromCache ->
                maybeFollowRedirect(responseFromCache, redirectQuery, finalRedirectCount));
  }

  /** Returns a LookupResult if this response was a non-exceptional empty result, else null. */
  private static LookupResult buildResult(Message answer, List<Name> aliases, Record query) {
    int rcode = answer.getRcode();
    List<Record> answerRecords = answer.getSection(Section.ANSWER);
    if (answerRecords.isEmpty() && rcode != Rcode.NOERROR) {
      switch (rcode) {
        case Rcode.NXDOMAIN:
          throw new NoSuchDomainException(query.getName(), query.getType());
        case Rcode.NXRRSET:
          throw new NoSuchRRSetException(query.getName(), query.getType());
        case Rcode.SERVFAIL:
          throw new ServerFailedException();
        default:
          throw new LookupFailedException(
              String.format("Unknown non-success error code %s", Rcode.string(rcode)));
      }
    }
    return new LookupResult(answerRecords, aliases);
  }
}
