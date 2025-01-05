// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs
package org.xbill.DNS.dnssec;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

/**
 * This class represents a DNS message with validator state and some utility methods.
 *
 * @since 3.5
 */
@Slf4j
final class SMessage {
  private static final int NUM_SECTIONS = 3;
  private static final int MAX_FLAGS = 16;
  private static final int EXTENDED_FLAGS_BIT_OFFSET = 4;

  private final Header header;
  private Record question;
  private OPTRecord oPTRecord;
  private final List<SRRset>[] sections;
  private SecurityStatus securityStatus;
  private String bogusReason;
  private int edeReason = -1;

  /**
   * Creates a instance of this class.
   *
   * @param h The header of the original message.
   */
  @SuppressWarnings("unchecked")
  public SMessage(Header h) {
    this.sections = (List<SRRset>[]) new List<?>[NUM_SECTIONS];
    this.header = h;
    this.securityStatus = SecurityStatus.UNCHECKED;
  }

  /**
   * Creates a new instance of this class.
   *
   * @param id The ID of the DNS query or response message.
   * @param question The question section of the query or response.
   */
  public SMessage(int id, Record question) {
    this(new Header(id));
    this.question = question;
  }

  /**
   * Creates a new instance of this class.
   *
   * @param m The DNS message to wrap.
   */
  public SMessage(Message m) {
    this(m.getHeader());
    this.question = m.getQuestion();
    this.oPTRecord = m.getOPT();

    for (int i = Section.ANSWER; i <= Section.ADDITIONAL; i++) {
      for (RRset rrset : m.getSectionRRsets(i)) {
        this.addRRset(new SRRset(rrset), i);
      }
    }
  }

  /**
   * Gets the header of this message.
   *
   * @return The header of this message.
   */
  public Header getHeader() {
    return this.header;
  }

  /**
   * Gets the question section of this message.
   *
   * @return The question section of this message.
   */
  public Record getQuestion() {
    return this.question;
  }

  /**
   * Gets signed RRsets for the queried section.
   *
   * @param section The section whose RRsets are demanded.
   * @return Signed RRsets for the queried section.
   */
  public List<SRRset> getSectionRRsets(int section) {
    this.checkSectionValidity(section);

    if (this.sections[section - 1] == null) {
      this.sections[section - 1] = new LinkedList<>();
    }

    return this.sections[section - 1];
  }

  private void addRRset(SRRset srrset, int section) {
    this.checkSectionValidity(section);

    if (srrset.getType() == Type.OPT) {
      this.oPTRecord = (OPTRecord) srrset.first();
      return;
    }

    List<SRRset> sectionList = this.getSectionRRsets(section);
    sectionList.add(srrset);
  }

  private void checkSectionValidity(int section) {
    if (section <= Section.QUESTION || section > Section.ADDITIONAL) {
      throw new IllegalArgumentException("Invalid section");
    }
  }

  /**
   * Gets signed RRsets for the queried section.
   *
   * @param section The section whose RRsets are demanded.
   * @param qtype Filter the results for these record types.
   * @return Signed RRsets for the queried section.
   */
  public List<SRRset> getSectionRRsets(int section, int qtype) {
    List<SRRset> slist = this.getSectionRRsets(section);

    if (slist.isEmpty()) {
      return Collections.emptyList();
    }

    List<SRRset> result = new ArrayList<>(slist.size());
    for (SRRset rrset : slist) {
      if (rrset.getType() == qtype) {
        result.add(rrset);
      }
    }

    return result;
  }

  /**
   * Gets the result code of the response message.
   *
   * @return The result code of the response message.
   */
  public int getRcode() {
    int rcode = this.header.getRcode();
    if (this.oPTRecord != null) {
      rcode += this.oPTRecord.getExtendedRcode() << EXTENDED_FLAGS_BIT_OFFSET;
    }

    return rcode;
  }

  /**
   * Gets the security status of this message.
   *
   * @return The security status of this message.
   */
  public SecurityStatus getStatus() {
    return this.securityStatus;
  }

  /**
   * Sets the security status for this message.
   *
   * @param status the new security status for this message.
   */
  public void setStatus(SecurityStatus status, int edeReason) {
    setStatus(status, edeReason, null);
  }

  /**
   * Sets the security status for this message.
   *
   * @param status the new security status for this message.
   * @param reason Why this message's status is set as indicated.
   */
  public void setStatus(SecurityStatus status, int edeReason, String reason) {
    this.securityStatus = status;
    this.edeReason = edeReason;
    this.bogusReason = reason;
    if (reason != null) {
      log.debug("Setting bad reason for message to {}", reason);
    }
  }

  /**
   * Sets the security status of this message to bogus and sets the reason.
   *
   * @param reason Why this message's status is bogus.
   */
  public void setBogus(String reason) {
    setStatus(SecurityStatus.BOGUS, ExtendedErrorCodeOption.DNSSEC_BOGUS, reason);
  }

  /**
   * Sets the security status of this message to bogus and sets the reason.
   *
   * @param reason Why this message's status is bogus.
   */
  public void setBogus(String reason, int edeReason) {
    setStatus(SecurityStatus.BOGUS, edeReason, reason);
  }

  /**
   * Gets the reason why this messages' status is bogus.
   *
   * @return The reason why this messages' status is bogus.
   */
  public String getBogusReason() {
    return this.bogusReason;
  }

  /**
   * Gets the {@link org.xbill.DNS.ExtendedErrorCodeOption} reason why this messages' status is
   * bogus.
   */
  public int getEdeReason() {
    return this.edeReason;
  }

  /**
   * Gets this message as a standard DNSJAVA message.
   *
   * @return This message as a standard DNSJAVA message.
   */
  public Message getMessage() {
    // Generate our new message.
    Message m = new Message(this.header.getID());

    // Convert the header
    // We do this for two reasons:
    // 1) setCount() is package scope, so we can't do that, and
    // 2) setting the header on a message after creating the
    // message frequently gets stuff out of sync, leading to malformed wire
    // format messages.
    Header h = m.getHeader();
    h.setOpcode(this.header.getOpcode());
    h.setRcode(this.header.getRcode());
    for (int i = 0; i < MAX_FLAGS; i++) {
      if (Flags.isFlag(i) && this.header.getFlag(i)) {
        h.setFlag(i);
      }
    }

    // Add all the records. -- this will set the counts correctly in the
    // message header.
    if (this.question != null) {
      m.addRecord(this.question, Section.QUESTION);
    }

    for (int sec = Section.ANSWER; sec <= Section.ADDITIONAL; sec++) {
      List<SRRset> slist = this.getSectionRRsets(sec);
      for (SRRset rrset : slist) {
        for (Record j : rrset.rrs()) {
          m.addRecord(j, sec);
        }

        for (RRSIGRecord j : rrset.sigs()) {
          m.addRecord(j, sec);
        }
      }
    }

    if (this.oPTRecord != null) {
      m.addRecord(this.oPTRecord, Section.ADDITIONAL);
    }

    return m;
  }

  /**
   * Gets the number of records.
   *
   * @param section The section for which the records are counted.
   * @return The number of records for the queried section.
   */
  public int getCount(int section) {
    if (section == Section.QUESTION) {
      return 1;
    }

    List<SRRset> sectionList = this.getSectionRRsets(section);
    if (sectionList.isEmpty()) {
      return 0;
    }

    int count = 0;
    for (SRRset sr : sectionList) {
      count += sr.size();
    }

    return count;
  }

  /**
   * Find a specific (S)RRset in a given section.
   *
   * @param name the name of the RRset.
   * @param type the type of the RRset.
   * @param dclass the class of the RRset.
   * @param section the section to look in (ANSWER to ADDITIONAL)
   * @return The SRRset if found, null otherwise.
   */
  public SRRset findRRset(Name name, int type, int dclass, int section) {
    this.checkSectionValidity(section);

    for (SRRset set : this.getSectionRRsets(section)) {
      if (set.getName().equals(name) && set.getType() == type && set.getDClass() == dclass) {
        return set;
      }
    }

    return null;
  }

  /**
   * Find an "answer" RRset. This will look for RRsets in the ANSWER section that match the
   * &lt;qname,qtype,qclass&gt;, without considering CNAMEs.
   *
   * @param qname The starting search name.
   * @param qtype The search type.
   * @param qclass The search class.
   * @return a SRRset matching the query.
   */
  public SRRset findAnswerRRset(Name qname, int qtype, int qclass) {
    return this.findRRset(qname, qtype, qclass, Section.ANSWER);
  }
}
