// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.InetAddress;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;

class LookupResultTest {
  private static final LookupResult PREVIOUS = new LookupResult(false);
  private static final ARecord A_RECORD =
      new ARecord(Name.fromConstantString("a."), DClass.IN, 0, InetAddress.getLoopbackAddress());

  @Test
  void ctor_nullRecords() {
    assertThrows(
        NullPointerException.class,
        () -> new LookupResult(PREVIOUS, null, null, false, null, Collections.emptyList()));
  }

  @Test
  void ctor_nullAliases() {
    assertThrows(
        NullPointerException.class,
        () -> new LookupResult(PREVIOUS, null, null, false, Collections.emptyList(), null));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void ctor_authOnly(boolean isAuthenticated) {
    LookupResult lookupResult = new LookupResult(isAuthenticated);
    assertEquals(isAuthenticated, lookupResult.isAuthenticated());
    assertEquals(0, lookupResult.getAliases().size());
    assertEquals(0, lookupResult.getRecords().size());
    assertEquals(0, lookupResult.getQueryResponsePairs().size());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void ctor_singleRecord(boolean isAuthenticated) {
    LookupResult lookupResult = new LookupResult(A_RECORD, isAuthenticated, A_RECORD);
    assertEquals(isAuthenticated, lookupResult.isAuthenticated());
    assertEquals(0, lookupResult.getAliases().size());
    assertEquals(1, lookupResult.getRecords().size());
    assertEquals(1, lookupResult.getQueryResponsePairs().size());
    assertNull(lookupResult.getQueryResponsePairs().get(A_RECORD));
  }

  @Test
  void getResult() {
    LookupResult lookupResult =
        new LookupResult(
            PREVIOUS, null, null, false, singletonList(A_RECORD), Collections.emptyList());
    assertEquals(singletonList(A_RECORD), lookupResult.getRecords());
  }

  @Test
  void getAliases() {
    Name name = Name.fromConstantString("b.");
    Record aRecord = new ARecord(name, DClass.IN, 0, InetAddress.getLoopbackAddress());
    LookupResult lookupResult =
        new LookupResult(PREVIOUS, null, null, false, singletonList(aRecord), singletonList(name));
    assertEquals(singletonList(name), lookupResult.getAliases());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void isAuthenticated(boolean isAuthenticated) {
    LookupResult lookupResult =
        new LookupResult(
            new LookupResult(isAuthenticated),
            null,
            null,
            isAuthenticated,
            singletonList(A_RECORD),
            Collections.emptyList());
    assertEquals(isAuthenticated, lookupResult.isAuthenticated());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void isAuthenticatedRequiresAllForTrue(boolean isAuthenticated) {
    Name nameA = Name.fromConstantString("a.");
    Name nameB = Name.fromConstantString("b.");
    Record cname = new CNAMERecord(nameA, DClass.IN, 0, nameB);
    Record a = new ARecord(nameB, DClass.IN, 0, InetAddress.getLoopbackAddress());
    LookupResult lookupResult1 = new LookupResult(isAuthenticated);
    LookupResult lookupResult2 =
        new LookupResult(lookupResult1, cname, null, true, singletonList(a), singletonList(nameA));
    assertEquals(isAuthenticated, lookupResult2.isAuthenticated());
  }
}
