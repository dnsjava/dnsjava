// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)
// Copyright (c) 2007-2023 NLnet Labs

package org.xbill.DNS;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

/**
 * A DNS Message. A message is the basic unit of communication between the client and server of a
 * DNS operation. A message consists of a Header and 4 message sections.
 *
 * @see Resolver
 * @see Header
 * @see Section
 * @author Brian Wellington
 */
@Slf4j
public class Message implements Cloneable {

  /** The maximum length of a message in wire format. */
  public static final int MAXLENGTH = 65535;

  private Header header;
  private List<Record>[] sections;
  private int size;
  private TSIG tsigkey;
  private TSIGRecord generatedTsig;
  private TSIGRecord querytsig;
  private int tsigerror;
  private Resolver resolver;

  int tsigstart;
  int tsigState;
  int sig0start;

  /** The message was not signed */
  static final int TSIG_UNSIGNED = 0;

  /** The message was signed and verification succeeded */
  static final int TSIG_VERIFIED = 1;

  /** The message was an unsigned message in multiple-message response */
  static final int TSIG_INTERMEDIATE = 2;

  /** The message was signed and no verification was attempted. */
  static final int TSIG_SIGNED = 3;

  /** The message was signed and verification failed, or was not signed when it should have been. */
  static final int TSIG_FAILED = 4;

  private static final Record[] emptyRecordArray = new Record[0];

  @SuppressWarnings("unchecked")
  private Message(Header header) {
    sections = new List[4];
    this.header = header;
  }

  /** Creates a new Message with the specified Message ID */
  public Message(int id) {
    this(new Header(id));
  }

  /** Creates a new Message with a random Message ID */
  public Message() {
    this(new Header());
  }

  /**
   * Creates a new Message with a random Message ID suitable for sending as a query.
   *
   * @param r A record containing the question
   */
  public static Message newQuery(Record r) {
    Message m = new Message();
    m.header.setOpcode(Opcode.QUERY);
    m.header.setFlag(Flags.RD);
    m.addRecord(r, Section.QUESTION);
    return m;
  }

  /**
   * Creates a new Message to contain a dynamic update. A random Message ID and the zone are filled
   * in.
   *
   * @param zone The zone to be updated
   */
  public static Message newUpdate(Name zone) {
    return new Update(zone);
  }

  Message(DNSInput in) throws IOException {
    this(new Header(in));
    boolean isUpdate = header.getOpcode() == Opcode.UPDATE;
    boolean truncated = header.getFlag(Flags.TC);
    try {
      for (int i = 0; i < 4; i++) {
        int count = header.getCount(i);
        if (count > 0) {
          sections[i] = new ArrayList<>(count);
        }
        for (int j = 0; j < count; j++) {
          int pos = in.current();
          Record rec = Record.fromWire(in, i, isUpdate);
          sections[i].add(rec);
          if (i == Section.ADDITIONAL) {
            if (rec.getType() == Type.TSIG) {
              tsigstart = pos;
              if (j != count - 1) {
                throw new WireParseException("TSIG is not the last record in the message");
              }
            }
            if (rec.getType() == Type.SIG) {
              SIGRecord sig = (SIGRecord) rec;
              if (sig.getTypeCovered() == 0) {
                sig0start = pos;
              }
            }
          }
        }
      }
    } catch (WireParseException e) {
      if (!truncated) {
        throw e;
      }
    }
    size = in.current();
  }

  /**
   * Creates a new Message from its DNS wire format representation
   *
   * @param b A byte array containing the DNS Message.
   */
  public Message(byte[] b) throws IOException {
    this(new DNSInput(b));
  }

  /**
   * Creates a new Message from its DNS wire format representation
   *
   * @param byteBuffer A ByteBuffer containing the DNS Message.
   */
  public Message(ByteBuffer byteBuffer) throws IOException {
    this(new DNSInput(byteBuffer));
  }

  /**
   * Replaces the Header with a new one.
   *
   * @see Header
   */
  public void setHeader(Header h) {
    header = h;
  }

  /**
   * Retrieves the Header.
   *
   * @see Header
   */
  public Header getHeader() {
    return header;
  }

  /**
   * Adds a record to a section of the Message, and adjusts the header.
   *
   * @see Record
   * @see Section
   */
  public void addRecord(Record r, int section) {
    if (sections[section] == null) {
      sections[section] = new LinkedList<>();
    }
    header.incCount(section);
    sections[section].add(r);
  }

  /**
   * Removes a record from a section of the Message, and adjusts the header.
   *
   * @see Record
   * @see Section
   */
  public boolean removeRecord(Record r, int section) {
    Section.check(section);
    if (sections[section] != null && sections[section].remove(r)) {
      header.decCount(section);
      return true;
    } else {
      return false;
    }
  }

  /**
   * Removes all records from a section of the Message, and adjusts the header.
   *
   * @see Record
   * @see Section
   */
  public void removeAllRecords(int section) {
    Section.check(section);
    sections[section] = null;
    header.setCount(section, 0);
  }

  /**
   * Determines if the given record is already present in the given section.
   *
   * @see Record
   * @see Section
   */
  public boolean findRecord(Record r, int section) {
    Section.check(section);
    return sections[section] != null && sections[section].contains(r);
  }

  /**
   * Determines if the given record is already present in any section.
   *
   * @see Record
   * @see Section
   */
  public boolean findRecord(Record r) {
    for (int i = Section.ANSWER; i <= Section.ADDITIONAL; i++) {
      if (sections[i] != null && sections[i].contains(r)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Determines if an RRset with the given name and type is already present in the given section.
   *
   * @see RRset
   * @see Section
   */
  public boolean findRRset(Name name, int type, int section) {
    Type.check(type);
    Section.check(section);
    if (sections[section] == null) {
      return false;
    }
    for (int i = 0; i < sections[section].size(); i++) {
      Record r = sections[section].get(i);
      if (r.getType() == type && name.equals(r.getName())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Determines if an RRset with the given name and type is already present in any section.
   *
   * @see RRset
   * @see Section
   */
  public boolean findRRset(Name name, int type) {
    return findRRset(name, type, Section.ANSWER)
        || findRRset(name, type, Section.AUTHORITY)
        || findRRset(name, type, Section.ADDITIONAL);
  }

  /**
   * Returns the first record in the QUESTION section.
   *
   * @see Record
   * @see Section
   */
  public Record getQuestion() {
    List<Record> l = sections[Section.QUESTION];
    if (l == null || l.isEmpty()) {
      return null;
    }
    return l.get(0);
  }

  /**
   * Returns the TSIG record from the ADDITIONAL section, if one is present.
   *
   * @see TSIGRecord
   * @see TSIG
   * @see Section
   */
  public TSIGRecord getTSIG() {
    int count = header.getCount(Section.ADDITIONAL);
    if (count == 0) {
      return null;
    }
    List<Record> l = sections[Section.ADDITIONAL];
    Record rec = l.get(count - 1);
    if (rec.type != Type.TSIG) {
      return null;
    }
    return (TSIGRecord) rec;
  }

  /**
   * Gets the generated {@link TSIGRecord}. Only valid if the messages has been converted to wire
   * format with {@link #toWire(int)} before.
   *
   * @return A generated TSIG record or {@code null}.
   */
  TSIGRecord getGeneratedTSIG() {
    return generatedTsig;
  }

  /**
   * Was this message signed by a TSIG?
   *
   * @see TSIG
   */
  public boolean isSigned() {
    return tsigState == TSIG_SIGNED || tsigState == TSIG_VERIFIED || tsigState == TSIG_FAILED;
  }

  /**
   * If this message was signed by a TSIG, was the TSIG verified?
   *
   * @see TSIG
   */
  public boolean isVerified() {
    return tsigState == TSIG_VERIFIED;
  }

  /**
   * Returns the OPT record from the ADDITIONAL section, if one is present.
   *
   * @see OPTRecord
   * @see Section
   */
  public OPTRecord getOPT() {
    for (Record r : getSection(Section.ADDITIONAL)) {
      if (r instanceof OPTRecord) {
        return (OPTRecord) r;
      }
    }
    return null;
  }

  /** Returns the message's rcode (error code). This incorporates the EDNS extended rcode. */
  public int getRcode() {
    int rcode = header.getRcode();
    OPTRecord opt = getOPT();
    if (opt != null) {
      rcode += opt.getExtendedRcode() << 4;
    }
    return rcode;
  }

  /**
   * Returns an array containing all records in the given section, or an empty array if the section
   * is empty.
   *
   * @see Record
   * @see Section
   * @deprecated use {@link #getSection(int)}
   */
  @Deprecated
  public Record[] getSectionArray(int section) {
    Section.check(section);
    if (sections[section] == null) {
      return emptyRecordArray;
    }
    List<Record> l = sections[section];
    return l.toArray(new Record[0]);
  }

  /**
   * Returns all records in the given section, or an empty list if the section is empty.
   *
   * @see Record
   * @see Section
   */
  public List<Record> getSection(int section) {
    Section.check(section);
    if (sections[section] == null) {
      return Collections.emptyList();
    }
    return Collections.unmodifiableList(sections[section]);
  }

  /**
   * Returns an array containing all records in the given section grouped into RRsets.
   *
   * @see RRset
   * @see Section
   */
  @SuppressWarnings("java:S1119") // label
  public List<RRset> getSectionRRsets(int section) {
    Section.check(section);
    if (sections[section] == null) {
      return Collections.emptyList();
    }

    List<RRset> sets = new LinkedList<>();
    record_iteration:
    for (Record rec : sections[section]) {
      for (int j = sets.size() - 1; j >= 0; j--) {
        RRset set = sets.get(j);
        if (rec.sameRRset(set)) {
          set.addRR(rec);

          // Existing set found, continue with the next record
          continue record_iteration;
        }
      }

      // No existing set found, create a new one
      sets.add(new RRset(rec));
    }

    return sets;
  }

  void toWire(DNSOutput out) {
    header.toWire(out);
    Compression c = new Compression();
    for (int i = 0; i < sections.length; i++) {
      if (sections[i] == null) {
        continue;
      }
      for (Record rec : sections[i]) {
        rec.toWire(out, i, c);
      }
    }
  }

  /* Returns the number of records not successfully rendered. */
  private int sectionToWire(DNSOutput out, int section, Compression c, int maxLength) {
    int n = sections[section].size();
    int pos = out.current();
    int rendered = 0;
    int count = 0;
    Record lastrec = null;

    for (int i = 0; i < n; i++) {
      Record rec = sections[section].get(i);
      if (section == Section.ADDITIONAL && rec instanceof OPTRecord) {
        continue;
      }

      if (lastrec != null && !rec.sameRRset(lastrec)) {
        pos = out.current();
        rendered = count;
      }
      lastrec = rec;
      rec.toWire(out, section, c);
      if (out.current() > maxLength) {
        out.jump(pos);
        return n - rendered;
      }
      count++;
    }
    return n - count;
  }

  /* Returns true if the message could be rendered. */
  private void toWire(DNSOutput out, int maxLength) {
    if (maxLength < Header.LENGTH) {
      return;
    }

    int tempMaxLength = maxLength;
    if (tsigkey != null) {
      tempMaxLength -= tsigkey.recordLength();
    }

    OPTRecord opt = getOPT();
    byte[] optBytes = null;
    if (opt != null) {
      optBytes = opt.toWire(Section.ADDITIONAL);
      tempMaxLength -= optBytes.length;
    }

    int startpos = out.current();
    header.toWire(out);
    Compression c = new Compression();
    int flags = header.getFlagsByte();
    int additionalCount = 0;
    for (int i = 0; i < 4; i++) {
      int skipped;
      if (sections[i] == null) {
        continue;
      }
      skipped = sectionToWire(out, i, c, tempMaxLength);
      if (skipped != 0 && i != Section.ADDITIONAL) {
        flags = Header.setFlag(flags, Flags.TC, true);
        out.writeU16At(header.getCount(i) - skipped, startpos + 4 + 2 * i);
        for (int j = i + 1; j < Section.ADDITIONAL; j++) {
          out.writeU16At(0, startpos + 4 + 2 * j);
        }
        break;
      }
      if (i == Section.ADDITIONAL) {
        additionalCount = header.getCount(i) - skipped;
      }
    }

    if (optBytes != null) {
      out.writeByteArray(optBytes);
      additionalCount++;
    }

    if (flags != header.getFlagsByte()) {
      out.writeU16At(flags, startpos + 2);
    }

    if (additionalCount != header.getCount(Section.ADDITIONAL)) {
      out.writeU16At(additionalCount, startpos + 10);
    }

    if (tsigkey != null) {
      TSIGRecord tsigrec = tsigkey.generate(this, out.toByteArray(), tsigerror, querytsig);

      tsigrec.toWire(out, Section.ADDITIONAL, c);
      generatedTsig = tsigrec;
      out.writeU16At(additionalCount + 1, startpos + 10);
    }
  }

  /**
   * Returns an array containing the wire format representation of the {@link Message}, but does not
   * do any additional processing (e.g. OPT/TSIG records, truncation).
   *
   * <p>Do NOT use this to actually transmit a message, use {@link #toWire(int)} instead.
   */
  public byte[] toWire() {
    DNSOutput out = new DNSOutput();
    toWire(out);
    size = out.current();
    return out.toByteArray();
  }

  /**
   * Returns an array containing the wire format representation of the Message with the specified
   * maximum length. This will generate a truncated message (with the TC bit) if the message doesn't
   * fit, and will also sign the message with the TSIG key set by a call to {@link #setTSIG(TSIG,
   * int, TSIGRecord)}. This method may return an empty byte array if the message could not be
   * rendered at all; this could happen if maxLength is smaller than a DNS header, for example.
   *
   * <p>Do NOT use this method in conjunction with {@link TSIG#apply(Message, TSIGRecord)}, it
   * produces inconsistent results! Use {@link #setTSIG(TSIG, int, TSIGRecord)} instead.
   *
   * @param maxLength The maximum length of the message.
   * @return The wire format of the message, or an empty array if the message could not be rendered
   *     into the specified length.
   * @see Flags
   * @see TSIG
   */
  public byte[] toWire(int maxLength) {
    DNSOutput out = new DNSOutput();
    toWire(out, maxLength);
    size = out.current();
    return out.toByteArray();
  }

  /**
   * Sets the TSIG key to sign a message.
   *
   * @param key The TSIG key.
   * @since 3.5.1
   */
  public void setTSIG(TSIG key) {
    setTSIG(key, Rcode.NOERROR, null);
  }

  /**
   * Sets the TSIG key and other necessary information to sign a message.
   *
   * @param key The TSIG key.
   * @param error The value of the TSIG error field.
   * @param querytsig If this is a response, the TSIG from the request.
   */
  public void setTSIG(TSIG key, int error, TSIGRecord querytsig) {
    this.tsigkey = key;
    this.tsigerror = error;
    this.querytsig = querytsig;
  }

  /**
   * Returns the size of the message. Only valid if the message has been converted to or from wire
   * format.
   */
  public int numBytes() {
    return size;
  }

  /**
   * Converts the given section of the Message to a String.
   *
   * @see Section
   */
  public String sectionToString(int section) {
    Section.check(section);
    StringBuilder sb = new StringBuilder();
    sectionToString(sb, section);
    return sb.toString();
  }

  private void sectionToString(StringBuilder sb, int i) {
    if (i > 3) {
      return;
    }

    for (Record rec : getSection(i)) {
      if (i == Section.QUESTION) {
        sb.append(";;\t").append(rec.name);
        sb.append(", type = ").append(Type.string(rec.type));
        sb.append(", class = ").append(DClass.string(rec.dclass));
      } else {
        if (!(rec instanceof OPTRecord)) {
          sb.append(rec);
        }
      }
      sb.append("\n");
    }
  }

  /** Converts the Message to a String. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    OPTRecord opt = getOPT();
    if (opt != null) {
      sb.append(header.toStringWithRcode(getRcode())).append("\n\n");
      opt.printPseudoSection(sb);
      sb.append('\n');
    } else {
      sb.append(header).append('\n');
    }
    if (isSigned()) {
      sb.append(";; TSIG ");
      if (isVerified()) {
        sb.append("ok");
      } else {
        sb.append("invalid");
      }
      sb.append('\n');
    }
    for (int i = 0; i < 4; i++) {
      if (header.getOpcode() != Opcode.UPDATE) {
        sb.append(";; ").append(Section.longString(i)).append(":\n");
      } else {
        sb.append(";; ").append(Section.updString(i)).append(":\n");
      }
      sectionToString(sb, i);
      sb.append("\n");
    }
    sb.append(";; Message size: ").append(numBytes()).append(" bytes");
    return sb.toString();
  }

  /**
   * Creates a copy of this Message. This is done by the Resolver before adding TSIG and OPT
   * records, for example.
   *
   * @see Resolver
   * @see TSIGRecord
   * @see OPTRecord
   */
  @Override
  @SneakyThrows(CloneNotSupportedException.class)
  @SuppressWarnings({"unchecked", "java:S2975"})
  public Message clone() {
    Message m = (Message) super.clone();
    m.sections = new List[sections.length];
    for (int i = 0; i < sections.length; i++) {
      if (sections[i] != null) {
        m.sections[i] = new LinkedList<>(sections[i]);
      }
    }
    m.header = header.clone();
    if (querytsig != null) {
      m.querytsig = (TSIGRecord) querytsig.cloneRecord();
    }
    if (generatedTsig != null) {
      m.generatedTsig = (TSIGRecord) generatedTsig.cloneRecord();
    }
    return m;
  }

  /** Sets the resolver that originally received this Message from a server. */
  public void setResolver(Resolver resolver) {
    this.resolver = resolver;
  }

  /** Gets the resolver that originally received this Message from a server. */
  public Optional<Resolver> getResolver() {
    return Optional.ofNullable(resolver);
  }

  /**
   * Checks if a record {@link Type} is allowed within a {@link Section}.
   *
   * @return {@code true} if the type is allowed, {@code false} otherwise.
   */
  boolean isTypeAllowedInSection(int type, int section) {
    Type.check(type);
    Section.check(section);
    switch (section) {
      case Section.AUTHORITY:
        if (type == Type.SOA
            || type == Type.NS
            || type == Type.DS
            || type == Type.NSEC
            || type == Type.NSEC3) {
          return true;
        }
        break;
      case Section.ADDITIONAL:
        if (type == Type.A || type == Type.AAAA) {
          return true;
        }
        break;
    }

    return !Boolean.parseBoolean(System.getProperty("dnsjava.harden_unknown_additional", "true"));
  }

  /**
   * Creates a normalized copy of this message by following xNAME chains, synthesizing CNAMEs from
   * DNAMEs if necessary, and removing illegal RRsets from {@link Section#AUTHORITY} and {@link
   * Section#ADDITIONAL}.
   *
   * <p>Normalization is only applied to {@link Rcode#NOERROR} and {@link Rcode#NXDOMAIN} responses.
   *
   * <p>This method is equivalent to calling {@link #normalize(Message, boolean)} with {@code
   * false}.
   *
   * @param query The query that produced this message.
   * @return {@code null} if the message could not be normalized or is otherwise invalid.
   * @since 3.6
   */
  public Message normalize(Message query) {
    try {
      return normalize(query, false);
    } catch (WireParseException e) {
      // Cannot happen with 'false'
    }

    return null;
  }

  /**
   * Creates a normalized copy of this message by following xNAME chains, synthesizing CNAMEs from
   * DNAMEs if necessary, and removing illegal RRsets from {@link Section#AUTHORITY} and {@link
   * Section#ADDITIONAL}.
   *
   * <p>Normalization is only applied to {@link Rcode#NOERROR} and {@link Rcode#NXDOMAIN} responses.
   *
   * @param query The query that produced this message.
   * @param throwOnIrrelevantRecord If {@code true}, throw an exception instead of silently ignoring
   *     irrelevant records.
   * @return {@code null} if the message could not be normalized or is otherwise invalid.
   * @throws WireParseException when {@code throwOnIrrelevantRecord} is {@code true} and an invalid
   *     or irrelevant record was found.
   * @since 3.6
   */
  public Message normalize(Message query, boolean throwOnIrrelevantRecord)
      throws WireParseException {
    if (getRcode() != Rcode.NOERROR && getRcode() != Rcode.NXDOMAIN) {
      return this;
    }

    Name sname = query.getQuestion().getName();
    List<RRset> answerSectionSets = getSectionRRsets(Section.ANSWER);
    List<RRset> additionalSectionSets = getSectionRRsets(Section.ADDITIONAL);
    List<RRset> authoritySectionSets = getSectionRRsets(Section.AUTHORITY);

    List<RRset> cleanedAnswerSection = new ArrayList<>();
    List<RRset> cleanedAuthoritySection = new ArrayList<>();
    List<RRset> cleanedAdditionalSection = new ArrayList<>();
    boolean hadNsInAuthority = false;

    // For the ANSWER section, remove all "irrelevant" records and add synthesized CNAMEs from
    // DNAMEs. This will strip out-of-order CNAMEs as well.
    for (int i = 0; i < answerSectionSets.size(); i++) {
      RRset rrset = answerSectionSets.get(i);
      Name oldSname = sname;

      if (rrset.getType() == Type.DNAME && sname.subdomain(rrset.getName())) {
        if (rrset.size() > 1) {
          String template =
              "Normalization failed in response to <{}/{}/{}> (id {}), found {} entries (instead of just one) in DNAME RRSet <{}/{}>";
          if (throwOnIrrelevantRecord) {
            throw new WireParseException(template.replace("{}", "%s"));
          }
          log.warn(
              template,
              sname,
              Type.string(query.getQuestion().getType()),
              DClass.string(query.getQuestion().getDClass()),
              getHeader().getID(),
              rrset.size(),
              rrset.getName(),
              DClass.string(rrset.getDClass()));
          return null;
        }

        // If DNAME was queried, don't attempt to synthesize CNAME
        if (query.getQuestion().getType() != Type.DNAME) {
          // The DNAME is valid, accept it
          cleanedAnswerSection.add(rrset);

          // Check if the next rrset is correct CNAME, otherwise synthesize a CNAME
          RRset nextRRSet = answerSectionSets.size() >= i + 2 ? answerSectionSets.get(i + 1) : null;
          DNAMERecord dname = ((DNAMERecord) rrset.first());
          try {
            // Validate that an existing CNAME matches what we would synthesize
            if (nextRRSet != null
                && nextRRSet.getType() == Type.CNAME
                && nextRRSet.getName().equals(sname)) {
              Name expected =
                  Name.concatenate(
                      nextRRSet.getName().relativize(dname.getName()), dname.getTarget());
              if (expected.equals(((CNAMERecord) nextRRSet.first()).getTarget())) {
                continue;
              }
            }

            // Add a synthesized CNAME; TTL=0 to avoid caching
            Name dnameTarget = sname.fromDNAME(dname);
            cleanedAnswerSection.add(
                new RRset(new CNAMERecord(sname, dname.getDClass(), 0, dnameTarget)));
            sname = dnameTarget;

            // In DNAME ANY response, can have data after DNAME
            if (query.getQuestion().getType() == Type.ANY) {
              for (i++; i < answerSectionSets.size(); i++) {
                rrset = answerSectionSets.get(i);
                if (rrset.getName().equals(oldSname)) {
                  cleanedAnswerSection.add(rrset);
                } else {
                  break;
                }
              }
            }

            continue;
          } catch (NameTooLongException e) {
            String template =
                "Normalization failed in response to <{}/{}/{}> (id {}), could not synthesize CNAME for DNAME <{}/{}>";
            if (throwOnIrrelevantRecord) {
              throw new WireParseException(template.replace("{}", "%s"), e);
            }
            log.warn(
                template,
                sname,
                Type.string(query.getQuestion().getType()),
                DClass.string(query.getQuestion().getDClass()),
                getHeader().getID(),
                rrset.getName(),
                DClass.string(rrset.getDClass()));
            return null;
          }
        }
      }

      // Ignore irrelevant records
      if (!sname.equals(rrset.getName())) {
        logOrThrow(
            throwOnIrrelevantRecord,
            "Ignoring irrelevant RRset <{}/{}/{}> in response to <{}/{}/{}> (id {})",
            rrset,
            sname,
            query);
        continue;
      }

      // Follow CNAMEs
      if (rrset.getType() == Type.CNAME && query.getQuestion().getType() != Type.CNAME) {
        if (rrset.size() > 1) {
          String template =
              "Found {} CNAMEs in <{}/{}> response to <{}/{}/{}> (id {}), removing all but the first";
          if (throwOnIrrelevantRecord) {
            throw new WireParseException(
                String.format(
                    template.replace("{}", "%s"),
                    rrset.rrs(false).size(),
                    rrset.getName(),
                    DClass.string(rrset.getDClass()),
                    sname,
                    Type.string(query.getQuestion().getType()),
                    DClass.string(query.getQuestion().getDClass()),
                    getHeader().getID()));
          }
          log.warn(
              template,
              rrset.rrs(false).size(),
              rrset.getName(),
              DClass.string(rrset.getDClass()),
              sname,
              Type.string(query.getQuestion().getType()),
              DClass.string(query.getQuestion().getDClass()),
              getHeader().getID());
          List<Record> cnameRRset = rrset.rrs(false);
          for (int cnameIndex = 1; cnameIndex < cnameRRset.size(); cnameIndex++) {
            rrset.deleteRR(cnameRRset.get(i));
          }
        }

        sname = ((CNAMERecord) rrset.first()).getTarget();
        cleanedAnswerSection.add(rrset);

        // In CNAME ANY response, can have data after CNAME
        if (query.getQuestion().getType() == Type.ANY) {
          for (i++; i < answerSectionSets.size(); i++) {
            rrset = answerSectionSets.get(i);
            if (rrset.getName().equals(oldSname)) {
              cleanedAnswerSection.add(rrset);
            } else {
              break;
            }
          }
        }

        continue;
      }

      // Remove records that don't match the queried type
      int qtype = getQuestion().getType();
      if (qtype != Type.ANY && rrset.getActualType() != qtype) {
        logOrThrow(
            throwOnIrrelevantRecord,
            "Ignoring irrelevant RRset <{}/{}/{}> in ANSWER section response to <{}/{}/{}> (id {})",
            rrset,
            sname,
            query);
        continue;
      }

      // Mark the additional names from relevant RRset as OK
      cleanedAnswerSection.add(rrset);
      if (sname.equals(rrset.getName())) {
        addAdditionalRRset(rrset, additionalSectionSets, cleanedAdditionalSection);
      }
    }

    for (RRset rrset : authoritySectionSets) {
      switch (rrset.getType()) {
        case Type.DNAME:
        case Type.CNAME:
        case Type.A:
        case Type.AAAA:
          logOrThrow(
              throwOnIrrelevantRecord,
              "Ignoring forbidden RRset <{}/{}/{}> in AUTHORITY section response to <{}/{}/{}> (id {})",
              rrset,
              sname,
              query);
          continue;
      }

      if (!isTypeAllowedInSection(rrset.getType(), Section.AUTHORITY)) {
        logOrThrow(
            throwOnIrrelevantRecord,
            "Ignoring disallowed RRset <{}/{}/{}> in AUTHORITY section response to <{}/{}/{}> (id {})",
            rrset,
            sname,
            query);
        continue;
      }

      if (rrset.getType() == Type.NS) {
        // NS set must be pertinent to the query
        if (!sname.subdomain(rrset.getName())) {
          logOrThrow(
              throwOnIrrelevantRecord,
              "Ignoring disallowed RRset <{}/{}/{}> in AUTHORITY section response to <{}/{}/{}> (id {}), not a subdomain of the query",
              rrset,
              sname,
              query);
          continue;
        }

        // We don't want NS sets for NODATA or NXDOMAIN answers, because they could contain
        // poisonous contents, from e.g. fragmentation attacks, inserted after long RRSIGs in the
        // packet get to the packet border and such
        if (getRcode() == Rcode.NXDOMAIN
            || (getRcode() == Rcode.NOERROR
                && authoritySectionSets.stream().anyMatch(set -> set.getType() == Type.SOA)
                && sections[Section.ANSWER] == null)) {
          logOrThrow(
              throwOnIrrelevantRecord,
              "Ignoring disallowed RRset <{}/{}/{}> in AUTHORITY section response to <{}/{}/{}> (id {}), NXDOMAIN or NODATA",
              rrset,
              sname,
              query);
          continue;
        }

        if (!hadNsInAuthority) {
          hadNsInAuthority = true;
        } else {
          logOrThrow(
              throwOnIrrelevantRecord,
              "Ignoring disallowed RRset <{}/{}/{}> in AUTHORITY section response to <{}/{}/{}> (id {}), already seen another NS",
              rrset,
              sname,
              query);
          continue;
        }
      }

      cleanedAuthoritySection.add(rrset);
      addAdditionalRRset(rrset, additionalSectionSets, cleanedAdditionalSection);
    }

    Message cleanedMessage = new Message(this.getHeader());
    cleanedMessage.sections[Section.QUESTION] = this.sections[Section.QUESTION];
    cleanedMessage.sections[Section.ANSWER] = rrsetListToRecords(cleanedAnswerSection);
    cleanedMessage.sections[Section.AUTHORITY] = rrsetListToRecords(cleanedAuthoritySection);
    cleanedMessage.sections[Section.ADDITIONAL] = rrsetListToRecords(cleanedAdditionalSection);
    return cleanedMessage;
  }

  private void logOrThrow(
      boolean throwOnIrrelevantRecord, String format, RRset rrset, Name sname, Message query)
      throws WireParseException {
    if (throwOnIrrelevantRecord) {
      throw new WireParseException(
          String.format(
              format.replace("{}", "%s") + this,
              rrset.getName(),
              DClass.string(rrset.getDClass()),
              Type.string(rrset.getType()),
              sname,
              Type.string(query.getQuestion().getType()),
              DClass.string(query.getQuestion().getDClass()),
              getHeader().getID()));
    }
    log.debug(
        format,
        rrset.getName(),
        DClass.string(rrset.getDClass()),
        Type.string(rrset.getType()),
        sname,
        Type.string(query.getQuestion().getType()),
        DClass.string(query.getQuestion().getDClass()),
        getHeader().getID());
  }

  private List<Record> rrsetListToRecords(List<RRset> rrsets) {
    if (rrsets.isEmpty()) {
      return null;
    }

    List<Record> result = new ArrayList<>(rrsets.size());
    for (RRset set : rrsets) {
      result.addAll(set.rrs(false));
      result.addAll(set.sigs());
    }

    return result;
  }

  private void addAdditionalRRset(
      RRset rrset, List<RRset> additionalSectionSets, List<RRset> cleanedAdditionalSection) {
    if (!doesTypeHaveAdditionalRecords(rrset.getType())) {
      return;
    }

    for (Record r : rrset.rrs(false)) {
      for (RRset set : additionalSectionSets) {
        if (set.getName().equals(r.getAdditionalName())
            && isTypeAllowedInSection(set.getType(), Section.ADDITIONAL)) {
          cleanedAdditionalSection.add(set);
        }
      }
    }
  }

  private boolean doesTypeHaveAdditionalRecords(int type) {
    switch (type) {
      case Type.MB:
      case Type.MD:
      case Type.MF:
      case Type.NS:
      case Type.MX:
      case Type.KX:
      case Type.SRV:
      case Type.NAPTR:
        return true;
    }

    return false;
  }
}
