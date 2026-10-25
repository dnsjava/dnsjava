// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;
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
    assertThat(R.get("key")).isEqualTo("key");
    assertThat(R.get("msg {0}", 1)).isEqualTo("msg 1");
  }

  @Test
  void testExplicitNullBundle() {
    R.setUseNeutralMessages(true);
    assertThat(R.get("key")).isEqualTo("key");
    assertThat(R.get("key", 1)).isEqualTo("key:1");
  }

  @Test
  void testNormal() {
    R.setUseNeutralMessages(false);
    R.setBundle(null);
    assertThat(R.get("test.noparam")).isEqualTo("no parameters");
    assertThat(R.get("test.withparam", "abc")).isEqualTo("parameter: abc");
  }

  @Test
  void testMissingResource() {
    R.setUseNeutralMessages(false);
    R.setBundle(null);
    assertThat(R.get("test.notthere.noparam")).isEqualTo("test.notthere.noparam");
    assertThat(R.get("test.notthere.withparam", "abc")).isEqualTo("test.notthere.withparam:abc");
    assertThat(R.get("test.notthere.withparam", "abc", null, 1))
        .isEqualTo("test.notthere.withparam:abc:null:1");
  }
}
