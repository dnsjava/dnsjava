// Copyright (c) 2002-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;

/**
 * The Lookup object issues queries to caching DNS servers. The input consists of a name, an
 * optional type, and an optional class. Caching is enabled by default and used when possible to
 * reduce the number of DNS requests. A Resolver, which defaults to an ExtendedResolver initialized
 * with the resolvers located by the ResolverConfig class, performs the queries. A search path of
 * domain suffixes is used to resolve relative names, and is also determined by the ResolverConfig
 * class.
 *
 * <p>A Lookup object may be reused, but should not be used by multiple threads.
 *
 * @see Cache
 * @see Resolver
 * @see ResolverConfig
 * @author Brian Wellington
 */
@Slf4j
public final class Lookup {

  private static Resolver defaultResolver;
  private static List<Name> defaultSearchPath;
  private static Map<Integer, Cache> defaultCaches;
  private static int defaultNdots;
  private final LookupHelper lookupHelper;
  private final int dclass;

  private Resolver resolver;
  private List<Name> searchPath;
  private int ndots;
  private Cache cache;
  private boolean temporary_cache;
  private int credibility;
  private boolean cycleResults = true;
  private int maxIterations;

  private static final Name[] noAliases = new Name[0];

  /** The lookup was successful. */
  public static final int SUCCESSFUL = 0;

  /** The lookup failed due to a data or server error. Repeating the lookup would not be helpful. */
  public static final int UNRECOVERABLE = 1;

  /** The lookup failed due to a network error. Repeating the lookup may be helpful. */
  public static final int TRY_AGAIN = 2;

  /** The host does not exist. */
  public static final int HOST_NOT_FOUND = 3;

  /** The host exists, but has no records associated with the queried type. */
  public static final int TYPE_NOT_FOUND = 4;

  public static synchronized void refreshDefault() {
    defaultResolver = new ExtendedResolver();
    defaultSearchPath = ResolverConfig.getCurrentConfig().searchPath();
    defaultCaches = new HashMap<>();
    defaultNdots = ResolverConfig.getCurrentConfig().ndots();
  }

  static {
    refreshDefault();
  }

  /**
   * Gets the Resolver that will be used as the default by future Lookups.
   *
   * @return The default resolver.
   */
  public static synchronized Resolver getDefaultResolver() {
    return defaultResolver;
  }

  /**
   * Sets the default Resolver to be used as the default by future Lookups.
   *
   * @param resolver The default resolver.
   */
  public static synchronized void setDefaultResolver(Resolver resolver) {
    defaultResolver = resolver;
  }

  /**
   * Gets the Cache that will be used as the default for the specified class by future Lookups.
   *
   * @param dclass The class whose cache is being retrieved.
   * @return The default cache for the specified class.
   */
  public static synchronized Cache getDefaultCache(int dclass) {
    DClass.check(dclass);
    Cache c = defaultCaches.get(dclass);
    if (c == null) {
      c = new Cache(dclass);
      defaultCaches.put(dclass, c);
    }
    return c;
  }

  /**
   * Sets the Cache to be used as the default for the specified class by future Lookups.
   *
   * @param cache The default cache for the specified class.
   * @param dclass The class whose cache is being set.
   */
  public static synchronized void setDefaultCache(Cache cache, int dclass) {
    DClass.check(dclass);
    defaultCaches.put(dclass, cache);
  }

  /**
   * Gets the search path that will be used as the default by future Lookups.
   *
   * @return The default search path.
   */
  public static synchronized List<Name> getDefaultSearchPath() {
    return defaultSearchPath;
  }

  /**
   * Sets the search path to be used as the default by future Lookups.
   *
   * @param domains The default search path.
   * @throws IllegalArgumentException if a domain in the search path is not absolute and cannot be
   *     made absolute.
   */
  public static synchronized void setDefaultSearchPath(List<Name> domains) {
    defaultSearchPath = convertSearchPathDomainList(domains);
  }

  /**
   * Sets the search path to be used as the default by future Lookups.
   *
   * @param domains The default search path.
   * @throws IllegalArgumentException if a domain in the search path is not absolute and cannot be
   *     made absolute.
   */
  public static synchronized void setDefaultSearchPath(Name... domains) {
    setDefaultSearchPath(Arrays.asList(domains));
  }

  /**
   * Sets the search path that will be used as the default by future Lookups.
   *
   * @param domains The default search path.
   * @throws TextParseException A name in the array is not a valid DNS name.
   */
  public static synchronized void setDefaultSearchPath(String... domains)
      throws TextParseException {
    if (domains == null) {
      defaultSearchPath = null;
      return;
    }

    List<Name> newdomains = new ArrayList<>(domains.length);
    for (String domain : domains) {
      newdomains.add(Name.fromString(domain, Name.root));
    }

    defaultSearchPath = newdomains;
  }

  private static List<Name> convertSearchPathDomainList(List<Name> domains) {
    try {
      return domains.stream()
          .map(
              n -> {
                try {
                  return Name.concatenate(n, Name.root);
                } catch (NameTooLongException e) {
                  throw new RuntimeException(e);
                }
              })
          .collect(Collectors.toList());
    } catch (RuntimeException e) {
      if (e.getCause() instanceof NameTooLongException) {
        throw new IllegalArgumentException(e.getCause());
      } else {
        throw e;
      }
    }
  }

  /**
   * Sets a custom logger that will be used to log the sent and received packets.
   *
   * @param logger The logger
   */
  public static synchronized void setPacketLogger(PacketLogger logger) {
    Client.setPacketLogger(logger);
  }

  /**
   * Create a Lookup object that will find records of the given name, type, and class. The lookup
   * will use the default cache, resolver, and search path, and look for records that are reasonably
   * credible.
   *
   * @param name The name of the desired records
   * @param type The type of the desired records
   * @param dclass The class of the desired records
   * @throws IllegalArgumentException The type is a meta type other than ANY.
   * @see Cache
   * @see Resolver
   * @see Credibility
   * @see Name
   * @see Type
   * @see DClass
   */
  public Lookup(Name name, int type, int dclass) {
    this.dclass = dclass;

    lookupHelper = new LookupHelper(name, type, dclass);
  }

  /**
   * Create a Lookup object that will find records of the given name and type in the IN class.
   *
   * @param name The name of the desired records
   * @param type The type of the desired records
   * @throws IllegalArgumentException The type is a meta type other than ANY.
   * @see #Lookup(Name,int,int)
   */
  public Lookup(Name name, int type) {
    this(name, type, DClass.IN);
  }

  /**
   * Create a Lookup object that will find records of type A at the given name in the IN class.
   *
   * @param name The name of the desired records
   * @see #Lookup(Name,int,int)
   */
  public Lookup(Name name) {
    this(name, Type.A, DClass.IN);
  }

  /**
   * Create a Lookup object that will find records of the given name, type, and class.
   *
   * @param name The name of the desired records
   * @param type The type of the desired records
   * @param dclass The class of the desired records
   * @throws TextParseException The name is not a valid DNS name
   * @throws IllegalArgumentException The type is a meta type other than ANY.
   * @see #Lookup(Name,int,int)
   */
  public Lookup(String name, int type, int dclass) throws TextParseException {
    this(Name.fromString(name), type, dclass);
  }

  /**
   * Create a Lookup object that will find records of the given name and type in the IN class.
   *
   * @param name The name of the desired records
   * @param type The type of the desired records
   * @throws TextParseException The name is not a valid DNS name
   * @throws IllegalArgumentException The type is a meta type other than ANY.
   * @see #Lookup(Name,int,int)
   */
  public Lookup(String name, int type) throws TextParseException {
    this(Name.fromString(name), type, DClass.IN);
  }

  /**
   * Create a Lookup object that will find records of type A at the given name in the IN class.
   *
   * @param name The name of the desired records
   * @throws TextParseException The name is not a valid DNS name
   * @see #Lookup(Name,int,int)
   */
  public Lookup(String name) throws TextParseException {
    this(Name.fromString(name), Type.A, DClass.IN);
  }

  /**
   * Sets the resolver to use when performing this lookup. This overrides the default value.
   *
   * @param resolver The resolver to use.
   */
  public void setResolver(Resolver resolver) {
    this.resolver = resolver;
  }

  /**
   * Sets the search path to use when performing this lookup. This overrides the default value.
   *
   * @param domains An array of names containing the search path.
   * @throws IllegalArgumentException if a domain in the search path is not absolute and cannot be
   *     made absolute.
   */
  public void setSearchPath(List<Name> domains) {
    this.searchPath = convertSearchPathDomainList(domains);
  }

  /**
   * Sets the search path to use when performing this lookup. This overrides the default value.
   *
   * @param domains An array of names containing the search path.
   * @throws IllegalArgumentException if a domain in the search path is not absolute and cannot be
   *     made absolute.
   */
  public void setSearchPath(Name... domains) {
    setSearchPath(Arrays.asList(domains));
  }

  /**
   * Sets the search path to use when performing this lookup. This overrides the default value.
   *
   * @param domains An array of names containing the search path.
   * @throws TextParseException A name in the array is not a valid DNS name.
   */
  public void setSearchPath(String... domains) throws TextParseException {
    if (domains == null) {
      this.searchPath = null;
      return;
    }

    List<Name> newdomains = new ArrayList<>(domains.length);
    for (String domain : domains) {
      newdomains.add(Name.fromString(domain, Name.root));
    }
    this.searchPath = newdomains;
  }

  /**
   * Sets the cache to use when performing this lookup. This overrides the default value. If the
   * results of this lookup should not be permanently cached, null can be provided here.
   *
   * @param cache The cache to use.
   */
  public void setCache(Cache cache) {
    if (cache == null) {
      this.cache = new Cache(dclass);
      this.temporary_cache = true;
    } else {
      this.cache = cache;
      this.temporary_cache = false;
    }
  }

  /**
   * Sets the default ndots to use when performing a lookup, overriding the default value.
   * Specifically, this refers to the number of "dots" which, if present in a name, indicate that a
   * lookup for the absolute name should be attempted before appending any search path elements.
   *
   * @param ndots The ndots value to use, which must be greater than or equal to 0.
   */
  public static void setDefaultNdots(int ndots) {
    if (ndots < 0) {
      throw new IllegalArgumentException("Illegal ndots value: " + ndots);
    }
    defaultNdots = ndots;
  }

  /**
   * Sets ndots to use when performing this lookup, overriding the default value. Specifically, this
   * refers to the number of "dots" which, if present in a name, indicate that a lookup for the
   * absolute name should be attempted before appending any search path elements.
   *
   * @param ndots The ndots value to use, which must be greater than or equal to 0.
   */
  public void setNdots(int ndots) {
    if (ndots < 0) {
      throw new IllegalArgumentException("Illegal ndots value: " + ndots);
    }
    this.ndots = ndots;
  }

  /**
   * Sets the minimum credibility level that will be accepted when performing the lookup. This
   * defaults to Credibility.NORMAL.
   *
   * @param credibility The minimum credibility level.
   */
  public void setCredibility(int credibility) {
    this.credibility = credibility;
  }

  /**
   * Controls the behavior if results being returned from the cache should be cycled in a
   * round-robin style (true) or if the raw lookup results should be returned (false).
   *
   * @param cycleResults The desired behavior of the order of the results
   */
  public void setCycleResults(boolean cycleResults) {
    this.cycleResults = cycleResults;
  }

  /**
   * Performs the lookup, using the specified Cache, Resolver, and search path.
   *
   * @return The answers, or null if none are found.
   */
  public Record[] run() {
    if (cache == null) {
      cache = getDefaultCache(dclass);
    }
    if (resolver == null) {
      resolver = getDefaultResolver();
    }
    if (searchPath == null) {
      searchPath = getDefaultSearchPath();
    }
    return lookupHelper.run(
        resolver,
        ndots,
        cache,
        searchPath,
        temporary_cache,
        credibility,
        cycleResults,
        maxIterations);
  }

  /**
   * Returns the answers from the lookup.
   *
   * @return The answers, or null if none are found.
   * @throws IllegalStateException The lookup has not completed.
   */
  public Record[] getAnswers() {
    return lookupHelper.getAnswers();
  }

  /**
   * Returns all known aliases for this name. Whenever a CNAME/DNAME is followed, an alias is added
   * to this array. The last element in this array will be the owner name for records in the answer,
   * if there are any.
   *
   * @return The aliases.
   * @throws IllegalStateException The lookup has not completed.
   */
  public Name[] getAliases() {
    return lookupHelper.getAliases();
  }

  /**
   * Returns the result code of the lookup.
   *
   * @return The result code, which can be SUCCESSFUL, UNRECOVERABLE, TRY_AGAIN, HOST_NOT_FOUND, or
   *     TYPE_NOT_FOUND.
   * @throws IllegalStateException The lookup has not completed.
   */
  public int getResult() {
    return lookupHelper.getResult();
  }

  /**
   * Returns an error string describing the result code of this lookup.
   *
   * @return A string, which may either directly correspond the result code or be more specific.
   * @throws IllegalStateException The lookup has not completed.
   */
  public String getErrorString() {
    return lookupHelper.getErrorString();
  }
}
