// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import lombok.extern.slf4j.Slf4j;

/**
 * An implementation of Resolver that sends one query to one server. SimpleResolver handles TCP
 * retries, transaction security (TSIG), and EDNS 0.
 *
 * @see Resolver
 * @see TSIG
 * @see OPTRecord
 * @author Brian Wellington
 */
@Slf4j
public class SimpleResolver implements Resolver {

  /** The default port to send queries to */
  public static final int DEFAULT_PORT = 53;

  /** The default EDNS payload size */
  public static final int DEFAULT_EDNS_PAYLOADSIZE = 1280;

  private InetSocketAddress address;
  private InetSocketAddress localAddress;
  private boolean useTCP, ignoreTruncation;
  private OPTRecord queryOPT = new OPTRecord(DEFAULT_EDNS_PAYLOADSIZE, 0, 0, 0);
  private TSIG tsig;
  private Duration timeoutValue = Duration.ofSeconds(10);

  private static final short DEFAULT_UDPSIZE = 512;

  private static InetSocketAddress defaultResolver =
      new InetSocketAddress(InetAddress.getLoopbackAddress(), DEFAULT_PORT);

  /**
   * Creates a SimpleResolver. The host to query is either found by using ResolverConfig, or the
   * default host is used.
   *
   * @see ResolverConfig
   * @exception UnknownHostException Failure occurred while finding the host
   */
  public SimpleResolver() throws UnknownHostException {
    this((String) null);
  }

  /**
   * Creates a SimpleResolver that will query the specified host
   *
   * @exception UnknownHostException Failure occurred while finding the host
   */
  public SimpleResolver(String hostname) throws UnknownHostException {
    if (hostname == null) {
      address = ResolverConfig.getCurrentConfig().server();
      if (address == null) {
        address = defaultResolver;
      }

      return;
    }

    InetAddress addr;
    if ("0".equals(hostname)) {
      addr = InetAddress.getLoopbackAddress();
    } else {
      addr = InetAddress.getByName(hostname);
    }

    address = new InetSocketAddress(addr, DEFAULT_PORT);
  }

  /** Creates a SimpleResolver that will query the specified host */
  public SimpleResolver(InetSocketAddress host) {
    address = Objects.requireNonNull(host, "host must not be null");
  }

  /** Creates a SimpleResolver that will query the specified host */
  public SimpleResolver(InetAddress host) {
    Objects.requireNonNull(host, "host must not be null");
    address = new InetSocketAddress(host, DEFAULT_PORT);
  }

  /**
   * Gets the destination address associated with this SimpleResolver. Messages sent using this
   * SimpleResolver will be sent to this address.
   *
   * @return The destination address associated with this SimpleResolver.
   */
  public InetSocketAddress getAddress() {
    return address;
  }

  /** Sets the default host (initially localhost) to query */
  public static void setDefaultResolver(InetSocketAddress hostname) {
    defaultResolver = hostname;
  }

  /** Sets the default host (initially localhost) to query */
  public static void setDefaultResolver(String hostname) {
    defaultResolver = new InetSocketAddress(hostname, DEFAULT_PORT);
  }

  /**
   * Gets the port to communicate with on the server
   *
   * @since 3.2
   */
  public int getPort() {
    return address.getPort();
  }

  @Override
  public void setPort(int port) {
    address = new InetSocketAddress(address.getAddress(), port);
  }

  /**
   * Sets the address of the server to communicate with.
   *
   * @param addr The address of the DNS server
   */
  public void setAddress(InetSocketAddress addr) {
    address = addr;
  }

  /**
   * Sets the address of the server to communicate with (on the default DNS port)
   *
   * @param addr The address of the DNS server
   */
  public void setAddress(InetAddress addr) {
    address = new InetSocketAddress(addr, address.getPort());
  }

  /**
   * Sets the local address to bind to when sending messages.
   *
   * @param addr The local address to send messages from.
   */
  public void setLocalAddress(InetSocketAddress addr) {
    localAddress = addr;
  }

  /**
   * Sets the local address to bind to when sending messages. A random port will be used.
   *
   * @param addr The local address to send messages from.
   */
  public void setLocalAddress(InetAddress addr) {
    localAddress = new InetSocketAddress(addr, 0);
  }

  /**
   * Gets whether TCP connections will be used by default
   *
   * @since 3.2
   */
  public boolean getTCP() {
    return useTCP;
  }

  @Override
  public void setTCP(boolean flag) {
    this.useTCP = flag;
  }

  /**
   * Gets whether truncated responses will be ignored.
   *
   * @since 3.2
   */
  public boolean getIgnoreTruncation() {
    return ignoreTruncation;
  }

  @Override
  public void setIgnoreTruncation(boolean flag) {
    this.ignoreTruncation = flag;
  }

  /**
   * Gets the EDNS information on outgoing messages.
   *
   * @return The current {@link OPTRecord} for EDNS or {@code null} if EDNS is disabled.
   * @since 3.2
   */
  public OPTRecord getEDNS() {
    return queryOPT;
  }

  /**
   * Sets the EDNS information on outgoing messages.
   *
   * @param optRecord the {@link OPTRecord} for EDNS options or null to disable EDNS.
   * @see #setEDNS(int, int, int, List)
   * @since 3.2
   */
  public void setEDNS(OPTRecord optRecord) {
    queryOPT = optRecord;
  }

  @Override
  public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
    switch (version) {
      case -1:
        queryOPT = null;
        break;

      case 0:
        if (payloadSize == 0) {
          payloadSize = DEFAULT_EDNS_PAYLOADSIZE;
        }
        queryOPT = new OPTRecord(payloadSize, 0, version, flags, options);
        break;

      default:
        throw new IllegalArgumentException("invalid EDNS version - must be 0 or -1 to disable");
    }
  }

  /**
   * Get the TSIG key that messages will be signed with.
   *
   * @return the TSIG signature for outgoing messages or {@code null} if not specified.
   * @since 3.2
   */
  public TSIG getTSIGKey() {
    return tsig;
  }

  @Override
  public void setTSIGKey(TSIG key) {
    tsig = key;
  }

  @Override
  public void setTimeout(Duration timeout) {
    timeoutValue = timeout;
  }

  @Override
  public Duration getTimeout() {
    return timeoutValue;
  }

  private Message parseMessage(byte[] b) throws WireParseException {
    try {
      return new Message(b);
    } catch (IOException e) {
      if (!(e instanceof WireParseException)) {
        e = new WireParseException("Error parsing message");
      }
      throw (WireParseException) e;
    }
  }

  private void verifyTSIG(Message query, Message response, byte[] b, TSIG tsig) {
    if (tsig == null) {
      return;
    }
    int error = tsig.verify(response, b, query.getTSIG());
    log.debug("TSIG verify: {}", Rcode.TSIGstring(error));
  }

  private void applyEDNS(Message query) {
    if (queryOPT == null || query.getOPT() != null) {
      return;
    }
    query.addRecord(queryOPT, Section.ADDITIONAL);
  }

  private int maxUDPSize(Message query) {
    OPTRecord opt = query.getOPT();
    if (opt == null) {
      return DEFAULT_UDPSIZE;
    } else {
      return opt.getPayloadSize();
    }
  }

  /**
   * Asynchronously sends a message to a single server, registering a listener to receive a callback
   * on success or exception. Multiple asynchronous lookups can be performed in parallel. Since the
   * callback may be invoked before the function returns, external synchronization is necessary.
   *
   * @param query The query to send
   * @return A future that completes when the response has arrived.
   */
  @Override
  public CompletionStage<Message> sendAsync(Message query) {
    if (query.getHeader().getOpcode() == Opcode.QUERY) {
      Record question = query.getQuestion();
      if (question != null && question.getType() == Type.AXFR) {
        CompletableFuture<Message> f = new CompletableFuture<>();
        CompletableFuture.runAsync(
            () -> {
              try {
                f.complete(sendAXFR(query));
              } catch (IOException e) {
                f.completeExceptionally(e);
              }
            });

        return f;
      }
    }

    Message ednsTsigQuery = query.clone();
    applyEDNS(ednsTsigQuery);
    if (tsig != null) {
      ednsTsigQuery.setTSIG(tsig, Rcode.NOERROR, null);
    }

    return sendAsync(ednsTsigQuery, useTCP);
  }

  CompletableFuture<Message> sendAsync(Message query, boolean forceTcp) {
    int qid = query.getHeader().getID();
    byte[] out = query.toWire(Message.MAXLENGTH);
    int udpSize = maxUDPSize(query);
    boolean tcp = forceTcp || out.length > udpSize;
    log.debug(
        "Sending {}/{}, id={} to {}/{}:{}",
        query.getQuestion().getName(),
        Type.string(query.getQuestion().getType()),
        qid,
        tcp ? "tcp" : "udp",
        address.getAddress().getHostAddress(),
        address.getPort());
    log.trace("Query:\n{}", query);

    CompletableFuture<?> result;
    if (tcp) {
      result = NioTcpClient.sendrecv(localAddress, address, query, out, timeoutValue);
    } else {
      result = NioUdpClient.sendrecv(localAddress, address, out, udpSize, timeoutValue);
    }

    return result.thenComposeAsync(
        v -> {
          CompletableFuture<Message> f = new CompletableFuture<>();

          Verify1Response verify1Response = new Verify1Response(query, qid);
          if (v instanceof byte[]) {
            byte[] in = (byte[])v;
            Message response = verify1Response.parse(in);
            if (response == null) {
              f.completeExceptionally(verify1Response.getExc());
              return f;
            }

            verifyTSIG(query, response, in, tsig);
            if (!tcp && !ignoreTruncation && response.getHeader().getFlag(Flags.TC)) {
              log.debug("Got truncated response for id {}, retrying via TCP", qid);
              log.trace("Truncated response: {}", response);
              return sendAsync(query, true);
            }

            response.setResolver(this);
            f.complete(response);
          } else if (v instanceof ArrayList) {
            @SuppressWarnings("unchecked")
            ArrayList<byte[]> list = (ArrayList<byte[]>)v;
            Message response = null;
            Throwable exc = null;
            for (byte[] in : list) {
              Message r = verify1Response.parse(in);
              if (r == null) {
                exc = verify1Response.getExc();
                continue;
              }

              verifyTSIG(query, r, in, tsig);
              if (!tcp && !ignoreTruncation && r.getHeader().getFlag(Flags.TC)) {
                log.debug("Got truncated response for id {}, discarding`", qid);
                log.trace("Truncated response: {}", r);
                continue;
              }

              if (response == null) {
                response = r;
              } else {
                // not the first answer, append the results to first response
                for (Record rec : r.getSection(Section.ANSWER)) {
                  response.addRecord(rec, Section.ANSWER);
                }
                for (Record rec : r.getSection(Section.AUTHORITY)) {
                  response.addRecord(rec, Section.AUTHORITY);
                }
                for (Record rec : r.getSection(Section.ADDITIONAL)) {
                  response.addRecord(rec, Section.ADDITIONAL);
                }
              }
            }

            if (response != null) {
              response.setResolver(this);
              f.complete(response);
            } else {
              if (exc == null) {
                exc = new SocketTimeoutException("Query timed out");
              }
              f.completeExceptionally(exc);
            }
          }
          return f;
        });
  }

  private Message sendAXFR(Message query) throws IOException {
    Name qname = query.getQuestion().getName();
    ZoneTransferIn xfrin = ZoneTransferIn.newAXFR(qname, address, tsig);
    xfrin.setTimeout(timeoutValue);
    xfrin.setLocalAddress(localAddress);
    try {
      xfrin.run();
    } catch (ZoneTransferException e) {
      throw new WireParseException(e.getMessage());
    }
    List<Record> records = xfrin.getAXFR();
    Message response = new Message(query.getHeader().getID());
    response.getHeader().setFlag(Flags.AA);
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(query.getQuestion(), Section.QUESTION);
    for (Record record : records) {
      response.addRecord(record, Section.ANSWER);
    }
    return response;
  }

  @Override
  public String toString() {
    return "SimpleResolver [" + address + "]";
  }

  private class Verify1Response {
    private Message query;
    private int qid;
    private Throwable exc;

    public Verify1Response(Message query, int qid) {
      this.query = query;
      this.qid = qid;
    }

    public Throwable getExc() {
      return exc;
    }

    public Message parse(byte[] in) {
      exc = null;

      // Check that the response is long enough.
      if (in.length < Header.LENGTH) {
        exc = new WireParseException("invalid DNS header - too short");
        return null;
      }

      // Check that the response ID matches the query ID. We want
      // to check this before actually parsing the message, so that
      // if there's a malformed response that's not ours, it
      // doesn't confuse us.
      int id = ((in[0] & 0xFF) << 8) + (in[1] & 0xFF);
      if (id != qid) {
        exc = new WireParseException("invalid message id: expected " + qid + "; got id " + id);
        return null;
      }

      Message r;
      try {
        r = parseMessage(in);
      } catch (WireParseException e) {
        exc = e;
        return null;
      }

      // validate name, class and type (rfc5452#section-9.1)
      if (!query.getQuestion().getName().equals(r.getQuestion().getName())) {
        exc =
          new WireParseException(
            "invalid name in message: expected "
              + query.getQuestion().getName()
              + "; got "
              + r.getQuestion().getName());
        return null;
      }

      if (query.getQuestion().getDClass() != r.getQuestion().getDClass()) {
        exc =
          new WireParseException(
            "invalid class in message: expected "
              + DClass.string(query.getQuestion().getDClass())
              + "; got "
              + DClass.string(r.getQuestion().getDClass()));
        return null;
      }

      if (query.getQuestion().getType() != r.getQuestion().getType()) {
        exc =
          new WireParseException(
            "invalid type in message: expected "
              + Type.string(query.getQuestion().getType())
              + "; got "
              + Type.string(r.getQuestion().getType()));
        return null;
      }

      return r;
    }
  }
}
