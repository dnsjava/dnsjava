// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;

class LookupResultTest {
  @Test
  void ctor_nullRecords() {
    assertThrows(NullPointerException.class, () -> new LookupResult(null, null));
  }

  @Test
  void getResult() {
    Record record =
        new ARecord(Name.fromConstantString("a."), DClass.IN, 0, InetAddress.getLoopbackAddress());
    LookupResult lookupResult = new LookupResult(singletonList(record), null);
    assertEquals(singletonList(record), lookupResult.getRecords());
  }

  @Test
  void getAliases() {
    Name name = Name.fromConstantString("b.");
    Record record = new ARecord(name, DClass.IN, 0, InetAddress.getLoopbackAddress());
    LookupResult lookupResult = new LookupResult(singletonList(record), singletonList(name));
    assertEquals(singletonList(name), lookupResult.getAliases());
  }
}
