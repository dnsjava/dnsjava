package org.xbill.DNS;

import static java.lang.String.format;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.xbill.DNS.exceptions.AdditionalDetail;
import org.xbill.DNS.exceptions.InvalidZoneDataException;
import org.xbill.DNS.exceptions.LookupFailedException;
import org.xbill.DNS.exceptions.RedirectOverflowException;
import org.xbill.DNS.exceptions.ServerFailedException;

/**
 * DNSSession provides facilities to make DNS Queries. A DNSSession is intended to be long lived,
 * and it's behaviour can be modified by calling the setter methods.
 */
public class DNSSession {
  private static final int DEFAULT_MAX_ITERATIONS = 16;

  private final Resolver resolver;
  private volatile int maxRedirects = DEFAULT_MAX_ITERATIONS;

  //  TODO: properties we want to support
  //    Cache cache,
  //    List<Name> searchPath,
  //    int ndots,
  //    boolean cycleResults,
  //    int credibility,
  //  ) {

  /**
   * Construct a DNSSession using the provided Resolver to lookup records.
   *
   * @param resolver the Resolver instance to backing this DNSSession.
   */
  DNSSession(Resolver resolver) {
    this.resolver = resolver;
  }

  /**
   * Sets the maximum number of CNAME or DNAME redirects allowed before lookups with fail with
   * RedirectOverflowException
   *
   * @param maxRedirects the maximum number of allowed redirections.
   */
  public void setMaxRedirects(int maxRedirects) {
    this.maxRedirects = maxRedirects;
  }

  /**
   * Make an asynchronous lookup of the provided name.
   *
   * @param name the name to look up
   * @param type the type to look up, values should correspond to constants in Type
   * @param dclass the class to look up, values should correspond to constants in DClass
   * @return A completion stage what will yield the eventual lookup
   */
  public CompletionStage<LookupResult> lookupAsync(Name name, int type, int dclass) {
    Record question = Record.newRecord(name, type, dclass);
    Message query = Message.newQuery(question);

    return resolver.sendAsync(query).thenCompose(this::resolveRedirects);
  }

  private CompletionStage<LookupResult> resolveRedirects(Message response) {
    CompletableFuture<LookupResult> future = new CompletableFuture<>();
    maybeFollowRedirect(response, 1, future);
    return future;
  }

  private void maybeFollowRedirect(
      Message response, int redirectCount, CompletableFuture<LookupResult> future) {
    try {
      if (redirectCount > maxRedirects) {
        throw new RedirectOverflowException(
            format("Refusing to follow more than %s redirects", maxRedirects));
      }

      List<Record> allAnswers = response.getSection(Section.ANSWER);
      LookupResult result = dealWithEmptyAnswer(allAnswers, response.getHeader().getRcode());
      if (result != null) {
        future.complete(result);
        return;
      }
      Record firstAnswer = allAnswers.get(0);

      if (firstAnswer.getType() == Type.DNAME || firstAnswer.getType() == Type.CNAME) {
        resolver
            .sendAsync(Message.newQuery(buildRedirectQuery(response)))
            .thenAccept(m -> maybeFollowRedirect(m, redirectCount + 1, future));
      } else {
        future.complete(new LookupResult(allAnswers, null));
      }
    } catch (LookupFailedException e) {
      future.completeExceptionally(e);
    }
  }

  private Record buildRedirectQuery(Message response) {
    List<Record> answer = response.getSection(Section.ANSWER);
    Record firstAnswer = answer.get(0);
    if (answer.size() != 1) {
      throw new InvalidZoneDataException("Multiple CNAME RRs not allowed, SEE RFC1034 3.6.2");
    }
    Record question = response.getQuestion();
    if (firstAnswer.getType() == Type.CNAME) {
      return Record.newRecord(
          ((CNAMERecord) firstAnswer).getTarget(), question.getType(), question.getDClass());
    }
    assert firstAnswer.getType() == Type.DNAME;
    try {
      Name name = question.getName().fromDNAME((DNAMERecord) firstAnswer);
      return Record.newRecord(name, question.getType(), question.getDClass());
    } catch (NameTooLongException e) {
      throw new InvalidZoneDataException(
          "DNAME redirect would result in a name that would be too long");
    }
  }

  /** Returns a LookupResult if there was one of the empty result one, else null. */
  private LookupResult dealWithEmptyAnswer(List<Record> answer, int rcode) {
    if (answer.isEmpty()) {
      switch (rcode) {
        case Rcode.NXDOMAIN:
          return new LookupResult(answer, AdditionalDetail.NXDOMAIN);
        case Rcode.NXRRSET:
          return new LookupResult(answer, AdditionalDetail.NXRRSET);
        case Rcode.SERVFAIL:
          throw new ServerFailedException();
        default:
          throw new LookupFailedException(format("Unknown non-success error code %d", rcode));
      }
    }
    return null;
  }
}
