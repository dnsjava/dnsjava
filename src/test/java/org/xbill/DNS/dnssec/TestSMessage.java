// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

class TestSMessage {
  @Test
  void testGetUndefinedSectionBelow() {
    SMessage m = new SMessage(0, null);
    assertThrows(IllegalArgumentException.class, () -> m.getSectionRRsets(-1));
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 4, 100})
  void testGetUndefinedSection(int section) {
    SMessage m = new SMessage(0, null);
    assertThrows(IllegalArgumentException.class, () -> m.getSectionRRsets(section));
  }

  @Test
  void testGetEmptySection() {
    SMessage m = new SMessage(0, null);
    List<SRRset> sets = m.getSectionRRsets(Section.ANSWER);
    assertEquals(0, sets.size());
  }

  @Test
  void testGetEmptySectionByType() {
    SMessage m = new SMessage(0, null);
    List<SRRset> sets = m.getSectionRRsets(Section.ANSWER, Type.A);
    assertEquals(0, sets.size());
  }

  @Test
  void testGetSectionByType() throws UnknownHostException {
    Message m = new Message();
    Record r1 =
        new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[] {0, 0, 0, 0}));
    m.addRecord(r1, Section.ANSWER);
    Record r2 =
        new AAAARecord(
            Name.root,
            DClass.IN,
            0,
            InetAddress.getByAddress(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}));
    m.addRecord(r2, Section.ANSWER);
    SMessage sm = new SMessage(m);
    List<SRRset> result = sm.getSectionRRsets(Section.ANSWER, Type.A);
    assertEquals(1, result.size());
    assertEquals(Type.A, result.get(0).getType());
  }

  @Test
  void testRecordCountForQuestionIsOne() {
    SMessage m = new SMessage(0, null);
    int count = m.getCount(Section.QUESTION);
    assertEquals(1, count);
  }

  @Test
  void testRecordCountForEmptySectionIsZero() {
    SMessage m = new SMessage(0, null);
    int count = m.getCount(Section.ADDITIONAL);
    assertEquals(0, count);
  }

  @Test
  void testRecordCountForIsValid() throws UnknownHostException {
    Message m = new Message();
    m.addRecord(
        new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[] {0, 0, 0, 0})),
        Section.ANSWER);
    SMessage sm = new SMessage(m);
    int count = sm.getCount(Section.ANSWER);
    assertEquals(1, count);
  }

  @Test
  void testAnswerSectionSearchFound() throws UnknownHostException {
    Message m = new Message();
    Record r =
        new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[] {0, 0, 0, 0}));
    m.addRecord(r, Section.ANSWER);
    SMessage sm = new SMessage(m);
    SRRset result = sm.findAnswerRRset(Name.root, Type.A, DClass.IN);
    assertEquals(r, result.first());
  }

  @Test
  void testAnswerSectionSearchNotFoundDifferentClass() throws UnknownHostException {
    Message m = new Message();
    Record r =
        new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[] {0, 0, 0, 0}));
    m.addRecord(r, Section.ANSWER);
    SMessage sm = new SMessage(m);
    SRRset result = sm.findAnswerRRset(Name.root, Type.A, DClass.CH);
    assertNull(result);
  }

  @Test
  void testAnswerSectionSearchNotFoundDifferentType() throws UnknownHostException {
    Message m = new Message();
    Record r =
        new ARecord(Name.root, DClass.IN, 0, InetAddress.getByAddress(new byte[] {0, 0, 0, 0}));
    m.addRecord(r, Section.ANSWER);
    SMessage sm = new SMessage(m);
    SRRset result = sm.findAnswerRRset(Name.root, Type.MX, DClass.IN);
    assertNull(result);
  }

  @Test
  void testAnswerSectionSearchNotFoundDifferentName()
      throws UnknownHostException, TextParseException {
    Message m = new Message();
    Record r =
        new ARecord(
            Name.fromString("asdf."),
            DClass.IN,
            0,
            InetAddress.getByAddress(new byte[] {0, 0, 0, 0}));
    m.addRecord(r, Section.ANSWER);
    SMessage sm = new SMessage(m);
    SRRset result = sm.findAnswerRRset(Name.root, Type.MX, DClass.IN);
    assertNull(result);
  }
}
