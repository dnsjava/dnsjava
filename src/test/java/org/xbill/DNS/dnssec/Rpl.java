// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.xbill.DNS.Message;

class Rpl {
  List<SRRset> trustAnchors = new ArrayList<>(1);
  Instant date;
  String scenario;
  List<Message> replays;
  Map<Integer, Check> checks;
  TreeMap<Integer, Integer> nsec3iterations;
  String digestPreference;
  boolean hardenAlgoDowngrade;
  boolean enableSha1;
  boolean enableDsa;
  boolean loadBouncyCastle;
}
