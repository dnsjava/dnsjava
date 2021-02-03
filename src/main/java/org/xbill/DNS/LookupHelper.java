package org.xbill.DNS;

import static org.xbill.DNS.Lookup.*;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;

@Slf4j
class LookupHelper {
  private Resolver resolver;
  private List<Name> searchPath;
  private Cache cache;
  private boolean temporary_cache;
  private int credibility;
  private Name name;
  private int type;
  private int dclass;
  private int iterations;
  private boolean foundAlias;
  private boolean done;
  private boolean doneCurrent;
  private List<Name> aliases;
  private Record[] answers;
  private int result;
  private String error;
  private boolean nxdomain;
  private boolean badresponse;
  private String badresponse_error;
  private boolean networkerror;
  private boolean timedout;
  private boolean nametoolong;
  private boolean referral;
  private boolean cycleResults = true;
  private int maxIterations;

  private static final Name[] noAliases = new Name[0];

  public LookupHelper(Name name, int type, int dclass) {
    Type.check(type);
    DClass.check(dclass);
    if (!Type.isRR(type) && type != Type.ANY) {
      throw new IllegalArgumentException("Cannot query for meta-types other than ANY");
    }
    this.name = name;
    this.type = type;
    this.dclass = dclass;
  }

  /**
   * Performs the lookup, using the specified Cache, Resolver, and search path.
   *
   * @return The answers, or null if none are found.
   */
  public Record[] run(
      Resolver resolver,
      int ndots,
      Cache cache,
      List<Name> searchPath,
      boolean temporary_cache,
      int credibility,
      boolean cycleResults,
      int maxIterations) {
    this.resolver = resolver;
    this.cache = cache;
    this.temporary_cache = temporary_cache;
    this.credibility = credibility;
    this.cycleResults = cycleResults;
    this.maxIterations = maxIterations;
    this.searchPath = searchPath;

    if (done) {
      reset();
    }
    if (name.isAbsolute()) {
      resolve(name, null);
    } else if (this.searchPath == null) {
      resolve(name, Name.root);
    } else {
      if (name.labels() > ndots) {
        resolve(name, Name.root);
      }
      if (done) {
        return answers;
      }

      for (Name value : this.searchPath) {
        resolve(name, value);
        if (done) {
          return answers;
        } else if (foundAlias) {
          break;
        }
      }

      resolve(name, Name.root);
    }
    if (!done) {
      if (badresponse) {
        result = TRY_AGAIN;
        error = badresponse_error;
        done = true;
      } else if (timedout) {
        result = TRY_AGAIN;
        error = "timed out";
        done = true;
      } else if (networkerror) {
        result = TRY_AGAIN;
        error = "network error";
        done = true;
      } else if (nxdomain) {
        result = HOST_NOT_FOUND;
        done = true;
      } else if (referral) {
        result = UNRECOVERABLE;
        error = "referral";
        done = true;
      } else if (nametoolong) {
        result = UNRECOVERABLE;
        error = "name too long";
        done = true;
      }
    }
    return answers;
  }

  /**
   * Returns the answers from the lookup.
   *
   * @return The answers, or null if none are found.
   * @throws IllegalStateException The lookup has not completed.
   */
  public Record[] getAnswers() {
    checkDone();
    return answers;
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
    checkDone();
    if (aliases == null) {
      return noAliases;
    }
    return aliases.toArray(new Name[0]);
  }

  /**
   * Returns the result code of the lookup.
   *
   * @return The result code, which can be SUCCESSFUL, UNRECOVERABLE, TRY_AGAIN, HOST_NOT_FOUND, or
   *     TYPE_NOT_FOUND.
   * @throws IllegalStateException The lookup has not completed.
   */
  public int getResult() {
    checkDone();
    return result;
  }

  /**
   * Returns an error string describing the result code of this lookup.
   *
   * @return A string, which may either directly correspond the result code or be more specific.
   * @throws IllegalStateException The lookup has not completed.
   */
  public String getErrorString() {
    checkDone();
    if (error != null) {
      return error;
    }
    switch (result) {
      case SUCCESSFUL:
        return "successful";
      case UNRECOVERABLE:
        return "unrecoverable error";
      case TRY_AGAIN:
        return "try again";
      case HOST_NOT_FOUND:
        return "host not found";
      case TYPE_NOT_FOUND:
        return "type not found";
    }
    throw new IllegalStateException("unknown result");
  }

  private void reset() {
    iterations = 0;
    foundAlias = false;
    done = false;
    doneCurrent = false;
    aliases = null;
    answers = null;
    result = -1;
    error = null;
    nxdomain = false;
    badresponse = false;
    badresponse_error = null;
    networkerror = false;
    timedout = false;
    nametoolong = false;
    referral = false;
    if (temporary_cache) {
      cache.clearCache();
    }
  }

  private void follow(Name name, Name oldname) {
    foundAlias = true;
    badresponse = false;
    networkerror = false;
    timedout = false;
    nxdomain = false;
    referral = false;
    iterations++;
    if (iterations >= maxIterations || name.equals(oldname)) {
      result = UNRECOVERABLE;
      error = "CNAME loop";
      done = true;
      return;
    }
    if (aliases == null) {
      aliases = new ArrayList<>();
    }
    aliases.add(oldname);
    lookup(name);
  }

  private void processResponse(Name name, SetResponse response) {
    if (response.isSuccessful()) {
      List<RRset> rrsets = response.answers();
      List<Record> l = new ArrayList<>();

      for (RRset set : rrsets) {
        l.addAll(set.rrs(cycleResults));
      }

      result = SUCCESSFUL;
      answers = l.toArray(new Record[0]);
      done = true;
    } else if (response.isNXDOMAIN()) {
      nxdomain = true;
      doneCurrent = true;
      if (iterations > 0) {
        result = HOST_NOT_FOUND;
        done = true;
      }
    } else if (response.isNXRRSET()) {
      result = TYPE_NOT_FOUND;
      answers = null;
      done = true;
    } else if (response.isCNAME()) {
      CNAMERecord cname = response.getCNAME();
      follow(cname.getTarget(), name);
    } else if (response.isDNAME()) {
      DNAMERecord dname = response.getDNAME();
      try {
        follow(name.fromDNAME(dname), name);
      } catch (NameTooLongException e) {
        result = UNRECOVERABLE;
        error = "Invalid DNAME target";
        done = true;
      }
    } else if (response.isDelegation()) {
      // We shouldn't get a referral.  Ignore it.
      referral = true;
    }
  }

  private void lookup(Name current) {
    SetResponse sr = cache.lookupRecords(current, type, credibility);
    log.debug("Lookup for {}/{}, cache answer: {}", current, Type.string(type), sr);

    processResponse(current, sr);
    if (done || doneCurrent) {
      return;
    }

    Record question = Record.newRecord(current, type, dclass);
    Message query = Message.newQuery(question);
    Message response;
    try {
      response = resolver.send(query);
    } catch (IOException e) {
      log.debug(
          "Lookup for {}/{}, id={} failed using resolver {}",
          current,
          Type.string(query.getQuestion().getType()),
          query.getHeader().getID(),
          resolver,
          e);

      // A network error occurred.  Press on.
      if (e instanceof InterruptedIOException) {
        timedout = true;
      } else {
        networkerror = true;
      }
      return;
    }
    int rcode = response.getHeader().getRcode();
    if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) {
      // The server we contacted is broken or otherwise unhelpful.
      // Press on.
      badresponse = true;
      badresponse_error = Rcode.string(rcode);
      return;
    }

    if (!query.getQuestion().equals(response.getQuestion())) {
      // The answer doesn't match the question.  That's not good.
      badresponse = true;
      badresponse_error = "response does not match query";
      return;
    }

    sr = cache.addMessage(response);
    if (sr == null) {
      sr = cache.lookupRecords(current, type, credibility);
    }

    log.debug(
        "Queried {}/{}, id={}: {}", current, Type.string(type), response.getHeader().getID(), sr);
    processResponse(current, sr);
  }

  private void resolve(Name current, Name suffix) {
    doneCurrent = false;
    Name tname;
    if (suffix == null) {
      tname = current;
    } else {
      try {
        tname = Name.concatenate(current, suffix);
      } catch (NameTooLongException e) {
        nametoolong = true;
        return;
      }
    }
    lookup(tname);
  }

  private void checkDone() {
    if (done && result != -1) {
      return;
    }
    StringBuilder sb = new StringBuilder("Lookup of " + name + " ");
    if (dclass != DClass.IN) {
      sb.append(DClass.string(dclass)).append(" ");
    }
    sb.append(Type.string(type)).append(" isn't done");
    throw new IllegalStateException(sb.toString());
  }
}
