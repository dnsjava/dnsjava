// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ResourceBundle;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;

class RTest {
  @Test
  void testCustomResourceBundle() {
    ResourceBundle rb = mock(ResourceBundle.class);
    when(rb.getString(anyString()))
        .then((Answer<String>) invocation -> (String) invocation.getArguments()[0]);
    R.setUseNeutralMessages(false);
    R.setBundle(rb);
    assertEquals("key", R.get("key"));
    assertEquals("msg 1", R.get("msg {0}", 1));
  }

  @Test
  void testExplicitNullBundle() {
    R.setUseNeutralMessages(true);
    assertEquals("key", R.get("key"));
    assertEquals("key:1", R.get("key", 1));
  }

  @Test
  void testNormal() {
    R.setUseNeutralMessages(false);
    R.setBundle(null);
    assertEquals("no parameters", R.get("test.noparam"));
    assertEquals("parameter: abc", R.get("test.withparam", "abc"));
  }

  @Test
  void testMissingResource() {
    R.setUseNeutralMessages(false);
    R.setBundle(null);
    assertEquals("test.notthere.noparam", R.get("test.notthere.noparam"));
    assertEquals("test.notthere.withparam:abc", R.get("test.notthere.withparam", "abc"));
    assertEquals(
        "test.notthere.withparam:abc:null:1", R.get("test.notthere.withparam", "abc", null, 1));
  }
}
