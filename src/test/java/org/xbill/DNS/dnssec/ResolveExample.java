// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

class ResolveExample {
  static String ROOT =
      ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

  static void main(String[] args) throws Exception {
    // Send two sample queries using a standard DNSJAVA resolver
    SimpleResolver sr = new SimpleResolver("8.8.8.8");
    System.out.println("Standard resolver:");
    sendAndPrint(sr, "www.dnssec-failed.org.");
    sendAndPrint(sr, "www.isc.org.");

    // Send the same queries using the validating resolver with the
    // trust anchor of the root zone
    // http://data.iana.org/root-anchors/root-anchors.xml
    ValidatingResolver vr = new ValidatingResolver(sr);
    vr.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes("ASCII")));
    vr.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes(StandardCharsets.US_ASCII)));
    System.out.println("\n\nValidating resolver:");
    sendAndPrint(vr, "www.dnssec-failed.org.");
    sendAndPrint(vr, "www.isc.org.");
  }

  private static void sendAndPrint(Resolver vr, String name) throws IOException {
    System.out.println("\n---" + name);
    Record qr = Record.newRecord(Name.fromConstantString(name), Type.A, DClass.IN);
    Message response = vr.send(Message.newQuery(qr));
    System.out.println("AD-Flag: " + response.getHeader().getFlag(Flags.AD));
    System.out.println("RCode:   " + Rcode.string(response.getRcode()));
    for (RRset set : response.getSectionRRsets(Section.ADDITIONAL)) {
      if (set.getName().equals(Name.root)
          && set.getType() == Type.TXT
          && set.getDClass() == ValidatingResolver.VALIDATION_REASON_QCLASS) {
        System.out.println("Reason:  " + ((TXTRecord) set.first()).getStrings().get(0));
      }
    }
  }
}
