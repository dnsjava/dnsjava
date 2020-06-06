// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;

/**
 * A cache of DNS records. The cache obeys TTLs, so items are purged after their validity period is
 * complete. Negative answers are cached, to avoid repeated failed DNS queries. The credibility of
 * each RRset is maintained, so that more credible records replace less credible records, and
 * lookups can specify the minimum credibility of data they are requesting.
 *
 * @see RRset
 * @see Credibility
 * @author Brian Wellington
 */
@Slf4j
public class Cache {

  private interface Element {
    boolean expired();

    int compareCredibility(int cred);

    int getType();
  }

  private static int limitExpire(long ttl, long maxttl) {
    if (maxttl >= 0 && maxttl < ttl) {
      ttl = maxttl;
    }
    long expire = (System.currentTimeMillis() / 1000) + ttl;
    if (expire < 0 || expire > Integer.MAX_VALUE) {
      return Integer.MAX_VALUE;
    }
    return (int) expire;
  }

  private static class CacheRRset extends RRset implements Element {
    private static final long serialVersionUID = 5971755205903597024L;

    int credibility;
    int expire;

    public CacheRRset(Record rec, int cred, long maxttl) {
      super();
      this.credibility = cred;
      this.expire = limitExpire(rec.getTTL(), maxttl);
      addRR(rec);
    }

    public CacheRRset(RRset rrset, int cred, long maxttl) {
      super(rrset);
      this.credibility = cred;
      this.expire = limitExpire(rrset.getTTL(), maxttl);
    }

    @Override
    public final boolean expired() {
      int now = (int) (System.currentTimeMillis() / 1000);
      return now >= expire;
    }

    @Override
    public final int compareCredibility(int cred) {
      return credibility - cred;
    }

    @Override
    public String toString() {
      return super.toString() + " cl = " + credibility;
    }
  }

  private static class NegativeElement implements Element {
    int type;
    Name name;
    int credibility;
    int expire;

    public NegativeElement(Name name, int type, SOARecord soa, int cred, long maxttl) {
      this.name = name;
      this.type = type;
      long cttl = 0;
      if (soa != null) {
        cttl = soa.getMinimum();
      }
      this.credibility = cred;
      this.expire = limitExpire(cttl, maxttl);
    }

    @Override
    public int getType() {
      return type;
    }

    @Override
    public final boolean expired() {
      int now = (int) (System.currentTimeMillis() / 1000);
      return now >= expire;
    }

    @Override
    public final int compareCredibility(int cred) {
      return credibility - cred;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      if (type == 0) {
        sb.append("NXDOMAIN ").append(name);
      } else {
        sb.append("NXRRSET ").append(name).append(" ").append(Type.string(type));
      }
      sb.append(" cl = ");
      sb.append(credibility);
      return sb.toString();
    }
  }

  private static class CacheMap extends LinkedHashMap<Name, Object> {
    private int maxsize;

    CacheMap(int maxsize) {
      super(16, (float) 0.75, true);
      this.maxsize = maxsize;
    }

    int getMaxSize() {
      return maxsize;
    }

    void setMaxSize(int maxsize) {
      /*
       * Note that this doesn't shrink the size of the map if
       * the maximum size is lowered, but it should shrink as
       * entries expire.
       */
      this.maxsize = maxsize;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry eldest) {
      return maxsize >= 0 && size() > maxsize;
    }
  }

  private CacheMap data;
  private int maxncache = -1;
  private int maxcache = -1;
  private int dclass;

  private static final int defaultMaxEntries = 50000;

  /**
   * Creates an empty Cache
   *
   * @param dclass The DNS class of this cache
   * @see DClass
   */
  public Cache(int dclass) {
    this.dclass = dclass;
    data = new CacheMap(defaultMaxEntries);
  }

  /**
   * Creates an empty Cache for class IN.
   *
   * @see DClass
   */
  public Cache() {
    this(DClass.IN);
  }

  /** Creates a Cache which initially contains all records in the specified file. */
  public Cache(String file) throws IOException {
    data = new CacheMap(defaultMaxEntries);
    try (Master m = new Master(file)) {
      Record record;
      while ((record = m.nextRecord()) != null) {
        addRecord(record, Credibility.HINT);
      }
    }
  }

  private synchronized Object exactName(Name name) {
    return data.get(name);
  }

  private synchronized void removeName(Name name) {
    data.remove(name);
  }

  private synchronized Element[] allElements(Object types) {
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<Element> typelist = (List<Element>) types;
      int size = typelist.size();
      return typelist.toArray(new Element[size]);
    } else {
      Element set = (Element) types;
      return new Element[] {set};
    }
  }

  private synchronized Element oneElement(Name name, Object types, int type, int minCred) {
    Element found = null;

    if (type == Type.ANY) {
      throw new IllegalArgumentException("oneElement(ANY)");
    }
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<Element> list = (List<Element>) types;
      for (Element set : list) {
        if (set.getType() == type) {
          found = set;
          break;
        }
      }
    } else {
      Element set = (Element) types;
      if (set.getType() == type) {
        found = set;
      }
    }
    if (found == null) {
      return null;
    }
    if (found.expired()) {
      removeElement(name, type);
      return null;
    }
    if (found.compareCredibility(minCred) < 0) {
      return null;
    }
    return found;
  }

  private synchronized Element findElement(Name name, int type, int minCred) {
    Object types = exactName(name);
    if (types == null) {
      return null;
    }
    return oneElement(name, types, type, minCred);
  }

  private synchronized void addElement(Name name, Element element) {
    Object types = data.get(name);
    if (types == null) {
      data.put(name, element);
      return;
    }
    int type = element.getType();
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<Element> list = (List<Element>) types;
      for (int i = 0; i < list.size(); i++) {
        Element elt = list.get(i);
        if (elt.getType() == type) {
          list.set(i, element);
          return;
        }
      }
      list.add(element);
    } else {
      Element elt = (Element) types;
      if (elt.getType() == type) {
        data.put(name, element);
      } else {
        LinkedList<Element> list = new LinkedList<>();
        list.add(elt);
        list.add(element);
        data.put(name, list);
      }
    }
  }

  private synchronized void removeElement(Name name, int type) {
    Object types = data.get(name);
    if (types == null) {
      return;
    }
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<Element> list = (List<Element>) types;
      for (int i = 0; i < list.size(); i++) {
        Element elt = list.get(i);
        if (elt.getType() == type) {
          list.remove(i);
          if (list.size() == 0) {
            data.remove(name);
          }
          return;
        }
      }
    } else {
      Element elt = (Element) types;
      if (elt.getType() != type) {
        return;
      }
      data.remove(name);
    }
  }

  /** Empties the Cache. */
  public synchronized void clearCache() {
    data.clear();
  }
  /**
   * Adds a record to the Cache.
   *
   * @param r The record to be added
   * @param cred The credibility of the record
   * @param o unused
   * @deprecated use {@link #addRecord(Record, int)}
   */
  @Deprecated
  public synchronized void addRecord(Record r, int cred, Object o) {
    addRecord(r, cred);
  }

  /**
   * Adds a record to the Cache.
   *
   * @param r The record to be added
   * @param cred The credibility of the record
   * @see Record
   */
  public synchronized void addRecord(Record r, int cred) {
    Name name = r.getName();
    int type = r.getRRsetType();
    if (!Type.isRR(type)) {
      return;
    }
    Element element = findElement(name, type, cred);
    if (element == null) {
      CacheRRset crrset = new CacheRRset(r, cred, maxcache);
      addRRset(crrset, cred);
    } else if (element.compareCredibility(cred) == 0) {
      if (element instanceof CacheRRset) {
        CacheRRset crrset = (CacheRRset) element;
        crrset.addRR(r);
      }
    }
  }

  /**
   * Adds an RRset to the Cache.
   *
   * @param rrset The RRset to be added
   * @param cred The credibility of these records
   * @see RRset
   */
  public synchronized <T extends Record> void addRRset(RRset rrset, int cred) {
    long ttl = rrset.getTTL();
    Name name = rrset.getName();
    int type = rrset.getType();
    Element element = findElement(name, type, 0);
    if (ttl == 0) {
      if (element != null && element.compareCredibility(cred) <= 0) {
        removeElement(name, type);
      }
    } else {
      if (element != null && element.compareCredibility(cred) <= 0) {
        element = null;
      }
      if (element == null) {
        CacheRRset crrset;
        if (rrset instanceof CacheRRset) {
          crrset = (CacheRRset) rrset;
        } else {
          crrset = new CacheRRset(rrset, cred, maxcache);
        }
        addElement(name, crrset);
      }
    }
  }

  /**
   * Adds a negative entry to the Cache.
   *
   * @param name The name of the negative entry
   * @param type The type of the negative entry
   * @param soa The SOA record to add to the negative cache entry, or null. The negative cache ttl
   *     is derived from the SOA.
   * @param cred The credibility of the negative entry
   */
  public synchronized void addNegative(Name name, int type, SOARecord soa, int cred) {
    long ttl = 0;
    if (soa != null) {
      ttl = soa.getTTL();
    }
    Element element = findElement(name, type, 0);
    if (ttl == 0) {
      if (element != null && element.compareCredibility(cred) <= 0) {
        removeElement(name, type);
      }
    } else {
      if (element != null && element.compareCredibility(cred) <= 0) {
        element = null;
      }
      if (element == null) {
        addElement(name, new NegativeElement(name, type, soa, cred, maxncache));
      }
    }
  }

  /** Finds all matching sets or something that causes the lookup to stop. */
  protected synchronized SetResponse lookup(Name name, int type, int minCred) {
    int labels;
    int tlabels;
    Element element;
    Name tname;
    Object types;
    SetResponse sr;

    labels = name.labels();

    for (tlabels = labels; tlabels >= 1; tlabels--) {
      boolean isRoot = tlabels == 1;
      boolean isExact = tlabels == labels;

      if (isRoot) {
        tname = Name.root;
      } else if (isExact) {
        tname = name;
      } else {
        tname = new Name(name, labels - tlabels);
      }

      types = data.get(tname);
      if (types == null) {
        continue;
      }

      /*
       * If this is the name, look for the actual type or a CNAME
       * (unless it's an ANY query, where we return everything).
       * Otherwise, look for a DNAME.
       */
      if (isExact && type == Type.ANY) {
        sr = new SetResponse(SetResponse.SUCCESSFUL);
        Element[] elements = allElements(types);
        int added = 0;
        for (Element value : elements) {
          element = value;
          if (element.expired()) {
            removeElement(tname, element.getType());
            continue;
          }
          if (!(element instanceof CacheRRset)) {
            continue;
          }
          if (element.compareCredibility(minCred) < 0) {
            continue;
          }
          sr.addRRset((CacheRRset) element);
          added++;
        }
        /* There were positive entries */
        if (added > 0) {
          return sr;
        }
      } else if (isExact) {
        element = oneElement(tname, types, type, minCred);
        if (element instanceof CacheRRset) {
          sr = new SetResponse(SetResponse.SUCCESSFUL);
          sr.addRRset((CacheRRset) element);
          return sr;
        } else if (element != null) {
          sr = new SetResponse(SetResponse.NXRRSET);
          return sr;
        }

        element = oneElement(tname, types, Type.CNAME, minCred);
        if (element instanceof CacheRRset) {
          return new SetResponse(SetResponse.CNAME, (CacheRRset) element);
        }
      } else {
        element = oneElement(tname, types, Type.DNAME, minCred);
        if (element instanceof CacheRRset) {
          return new SetResponse(SetResponse.DNAME, (CacheRRset) element);
        }
      }

      /* Look for an NS */
      element = oneElement(tname, types, Type.NS, minCred);
      if (element instanceof CacheRRset) {
        return new SetResponse(SetResponse.DELEGATION, (CacheRRset) element);
      }

      /* Check for the special NXDOMAIN element. */
      if (isExact) {
        element = oneElement(tname, types, 0, minCred);
        if (element != null) {
          return SetResponse.ofType(SetResponse.NXDOMAIN);
        }
      }
    }
    return SetResponse.ofType(SetResponse.UNKNOWN);
  }

  /**
   * Looks up Records in the Cache. This follows CNAMEs and handles negatively cached data.
   *
   * @param name The name to look up
   * @param type The type to look up
   * @param minCred The minimum acceptable credibility
   * @return A SetResponse object
   * @see SetResponse
   * @see Credibility
   */
  public SetResponse lookupRecords(Name name, int type, int minCred) {
    return lookup(name, type, minCred);
  }

  private List<RRset> findRecords(Name name, int type, int minCred) {
    SetResponse cr = lookupRecords(name, type, minCred);
    if (cr.isSuccessful()) {
      return cr.answers();
    } else {
      return null;
    }
  }

  /**
   * Looks up credible Records in the Cache (a wrapper around lookupRecords). Unlike lookupRecords,
   * this given no indication of why failure occurred.
   *
   * @param name The name to look up
   * @param type The type to look up
   * @return An array of RRsets, or null
   * @see Credibility
   */
  public List<RRset> findRecords(Name name, int type) {
    return findRecords(name, type, Credibility.NORMAL);
  }

  /**
   * Looks up Records in the Cache (a wrapper around lookupRecords). Unlike lookupRecords, this
   * given no indication of why failure occurred.
   *
   * @param name The name to look up
   * @param type The type to look up
   * @return An array of RRsets, or null
   * @see Credibility
   */
  public List<RRset> findAnyRecords(Name name, int type) {
    return findRecords(name, type, Credibility.GLUE);
  }

  private int getCred(int section, boolean isAuth) {
    if (section == Section.ANSWER) {
      if (isAuth) {
        return Credibility.AUTH_ANSWER;
      } else {
        return Credibility.NONAUTH_ANSWER;
      }
    } else if (section == Section.AUTHORITY) {
      if (isAuth) {
        return Credibility.AUTH_AUTHORITY;
      } else {
        return Credibility.NONAUTH_AUTHORITY;
      }
    } else if (section == Section.ADDITIONAL) {
      return Credibility.ADDITIONAL;
    } else {
      throw new IllegalArgumentException("getCred: invalid section");
    }
  }

  private static void markAdditional(RRset rrset, Set<Name> names) {
    Record first = rrset.first();
    if (first.getAdditionalName() == null) {
      return;
    }

    for (Record r : rrset.rrs()) {
      Name name = r.getAdditionalName();
      if (name != null) {
        names.add(name);
      }
    }
  }

  /**
   * Adds all data from a Message into the Cache. Each record is added with the appropriate
   * credibility, and negative answers are cached as such.
   *
   * @param in The Message to be added
   * @return A SetResponse that reflects what would be returned from a cache lookup, or null if
   *     nothing useful could be cached from the message.
   * @see Message
   */
  public SetResponse addMessage(Message in) {
    boolean isAuth = in.getHeader().getFlag(Flags.AA);
    Record question = in.getQuestion();
    Name qname;
    Name curname;
    int qtype;
    int qclass;
    int cred;
    int rcode = in.getHeader().getRcode();
    boolean completed = false;
    List<RRset> answers, auth, addl;
    SetResponse response = null;
    HashSet<Name> additionalNames;

    if ((rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) || question == null) {
      return null;
    }

    qname = question.getName();
    qtype = question.getType();
    qclass = question.getDClass();

    curname = qname;

    additionalNames = new HashSet<>();

    answers = in.getSectionRRsets(Section.ANSWER);
    for (RRset answer : answers) {
      if (answer.getDClass() != qclass) {
        continue;
      }
      int type = answer.getType();
      Name name = answer.getName();
      cred = getCred(Section.ANSWER, isAuth);
      if ((type == qtype || qtype == Type.ANY) && name.equals(curname)) {
        addRRset(answer, cred);
        completed = true;
        if (curname == qname) {
          if (response == null) {
            response = new SetResponse(SetResponse.SUCCESSFUL);
          }
          response.addRRset(answer);
        }
        markAdditional(answer, additionalNames);
      } else if (type == Type.CNAME && name.equals(curname)) {
        CNAMERecord cname;
        addRRset(answer, cred);
        if (curname == qname) {
          response = new SetResponse(SetResponse.CNAME, answer);
        }
        cname = (CNAMERecord) answer.first();
        curname = cname.getTarget();
      } else if (type == Type.DNAME && curname.subdomain(name)) {
        DNAMERecord dname;
        addRRset(answer, cred);
        if (curname == qname) {
          response = new SetResponse(SetResponse.DNAME, answer);
        }
        dname = (DNAMERecord) answer.first();
        try {
          curname = curname.fromDNAME(dname);
        } catch (NameTooLongException e) {
          break;
        }
      }
    }

    auth = in.getSectionRRsets(Section.AUTHORITY);
    RRset soa = null;
    RRset ns = null;
    for (RRset rset : auth) {
      if (rset.getType() == Type.SOA && curname.subdomain(rset.getName())) {
        soa = rset;
      } else if (rset.getType() == Type.NS && curname.subdomain(rset.getName())) {
        ns = rset;
      }
    }
    if (!completed) {
      /* This is a negative response or a referral. */
      int cachetype = (rcode == Rcode.NXDOMAIN) ? 0 : qtype;
      if (rcode == Rcode.NXDOMAIN || soa != null || ns == null) {
        /* Negative response */
        cred = getCred(Section.AUTHORITY, isAuth);
        SOARecord soarec = null;
        if (soa != null) {
          soarec = (SOARecord) soa.first();
        }
        addNegative(curname, cachetype, soarec, cred);
        if (response == null) {
          int responseType;
          if (rcode == Rcode.NXDOMAIN) {
            responseType = SetResponse.NXDOMAIN;
          } else {
            responseType = SetResponse.NXRRSET;
          }
          response = SetResponse.ofType(responseType);
        }
        /* DNSSEC records are not cached. */
      } else {
        /* Referral response */
        cred = getCred(Section.AUTHORITY, isAuth);
        addRRset(ns, cred);
        markAdditional(ns, additionalNames);
        if (response == null) {
          response = new SetResponse(SetResponse.DELEGATION, ns);
        }
      }
    } else if (rcode == Rcode.NOERROR && ns != null) {
      /* Cache the NS set from a positive response. */
      cred = getCred(Section.AUTHORITY, isAuth);
      addRRset(ns, cred);
      markAdditional(ns, additionalNames);
    }

    addl = in.getSectionRRsets(Section.ADDITIONAL);
    for (RRset rRset : addl) {
      int type = rRset.getType();
      if (type != Type.A && type != Type.AAAA && type != Type.A6) {
        continue;
      }
      Name name = rRset.getName();
      if (!additionalNames.contains(name)) {
        continue;
      }
      cred = getCred(Section.ADDITIONAL, isAuth);
      addRRset(rRset, cred);
    }

    log.debug(
        "Caching {} for {}/{}",
        response,
        in.getQuestion().getName(),
        Type.string(in.getQuestion().getType()));
    return response;
  }

  /**
   * Flushes an RRset from the cache
   *
   * @param name The name of the records to be flushed
   * @param type The type of the records to be flushed
   * @see RRset
   */
  public void flushSet(Name name, int type) {
    removeElement(name, type);
  }

  /**
   * Flushes all RRsets with a given name from the cache
   *
   * @param name The name of the records to be flushed
   * @see RRset
   */
  public void flushName(Name name) {
    removeName(name);
  }

  /**
   * Sets the maximum length of time that a negative response will be stored in this Cache. A
   * negative value disables this feature (that is, sets no limit).
   */
  public void setMaxNCache(int seconds) {
    maxncache = seconds;
  }

  /**
   * Gets the maximum length of time that a negative response will be stored in this Cache. A
   * negative value indicates no limit.
   */
  public int getMaxNCache() {
    return maxncache;
  }

  /**
   * Sets the maximum length of time that records will be stored in this Cache. A negative value
   * disables this feature (that is, sets no limit).
   */
  public void setMaxCache(int seconds) {
    maxcache = seconds;
  }

  /**
   * Gets the maximum length of time that records will be stored in this Cache. A negative value
   * indicates no limit.
   */
  public int getMaxCache() {
    return maxcache;
  }

  /**
   * Gets the current number of entries in the Cache, where an entry consists of all records with a
   * specific Name.
   */
  public int getSize() {
    return data.size();
  }

  /**
   * Gets the maximum number of entries in the Cache, where an entry consists of all records with a
   * specific Name. A negative value is treated as an infinite limit.
   */
  public int getMaxEntries() {
    return data.getMaxSize();
  }

  /**
   * Sets the maximum number of entries in the Cache, where an entry consists of all records with a
   * specific Name. A negative value is treated as an infinite limit.
   *
   * <p>Note that setting this to a value lower than the current number of entries will not cause
   * the Cache to shrink immediately.
   *
   * <p>The default maximum number of entries is 50000.
   *
   * @param entries The maximum number of entries in the Cache.
   */
  public void setMaxEntries(int entries) {
    data.setMaxSize(entries);
  }

  /** Returns the DNS class of this cache. */
  public int getDClass() {
    return dclass;
  }

  /** Returns the contents of the Cache as a string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    synchronized (this) {
      for (Object o : data.values()) {
        Element[] elements = allElements(o);
        for (Element element : elements) {
          sb.append(element);
          sb.append("\n");
        }
      }
    }
    return sb.toString();
  }
}
