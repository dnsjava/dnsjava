// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.SneakyThrows;

/**
 * A DNS Message. A message is the basic unit of communication between the client and server of a
 * DNS operation. A message consists of a Header and 4 message sections.
 *
 * @see Resolver
 * @see Header
 * @see Section
 * @author Brian Wellington
 */
public class Message implements Cloneable {

  /** The maximum length of a message in wire format. */
  public static final int MAXLENGTH = 65535;

  private Header header;
  private List<Record>[] sections;
  private int size;
  private TSIG tsigkey;
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
    if (l == null || l.size() == 0) {
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
    for (Record record : getSection(Section.ADDITIONAL)) {
      if (record instanceof OPTRecord) {
        return (OPTRecord) record;
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
    if (sections[section] == null) {
      return Collections.emptyList();
    }
    return Collections.unmodifiableList(sections[section]);
  }

  private static boolean sameSet(Record r1, Record r2) {
    return r1.getRRsetType() == r2.getRRsetType()
        && r1.getDClass() == r2.getDClass()
        && r1.getName().equals(r2.getName());
  }

  /**
   * Returns an array containing all records in the given section grouped into RRsets.
   *
   * @see RRset
   * @see Section
   */
  public List<RRset> getSectionRRsets(int section) {
    if (sections[section] == null) {
      return Collections.emptyList();
    }
    List<RRset> sets = new LinkedList<>();
    Set<Name> hash = new HashSet<>();
    for (Record rec : getSection(section)) {
      Name name = rec.getName();
      boolean newset = true;
      if (hash.contains(name)) {
        for (int j = sets.size() - 1; j >= 0; j--) {
          RRset set = sets.get(j);
          if (set.getType() == rec.getRRsetType()
              && set.getDClass() == rec.getDClass()
              && set.getName().equals(name)) {
            set.addRR(rec);
            newset = false;
            break;
          }
        }
      }
      if (newset) {
        RRset set = new RRset(rec);
        sets.add(set);
        hash.add(name);
      }
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

      if (lastrec != null && !sameSet(rec, lastrec)) {
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
   * fit, and will also sign the message with the TSIG key set by a call to setTSIG(). This method
   * may return an empty byte array if the message could not be rendered at all; this could happen
   * if maxLength is smaller than a DNS header, for example.
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
  public String sectionToString(int i) {
    if (i > 3) {
      return null;
    }

    StringBuilder sb = new StringBuilder();
    for (Record rec : getSection(i)) {
      if (i == Section.QUESTION) {
        sb.append(";;\t").append(rec.name);
        sb.append(", type = ").append(Type.string(rec.type));
        sb.append(", class = ").append(DClass.string(rec.dclass));
      } else {
        sb.append(rec);
      }
      sb.append("\n");
    }
    return sb.toString();
  }

  /** Converts the Message to a String. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    OPTRecord opt = getOPT();
    if (opt != null) {
      sb.append(header.toStringWithRcode(getRcode())).append("\n");
    } else {
      sb.append(header).append("\n");
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
      sb.append(sectionToString(i)).append("\n");
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
  @SuppressWarnings("unchecked")
  public Message clone() {
    Message m = (Message) super.clone();
    m.sections = (List<Record>[]) new List[sections.length];
    for (int i = 0; i < sections.length; i++) {
      if (sections[i] != null) {
        m.sections[i] = new LinkedList<>(sections[i]);
      }
    }
    m.header = header.clone();
    if (querytsig != null) {
      m.querytsig = (TSIGRecord) querytsig.cloneRecord();
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
}
