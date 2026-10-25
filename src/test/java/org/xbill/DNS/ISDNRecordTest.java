// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ISDNRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_5arg() {
    ISDNRecord isdn = new ISDNRecord(n, DClass.IN, 0, "foo\\\"", "bar");
    assertThat(isdn.getAddress()).isEqualTo("foo\\\"");
    assertThat(isdn.getAddress(false)).isEqualTo("foo\"");
    assertThat(isdn.getAddressAsByteArray())
        .containsExactly("foo\"".getBytes(StandardCharsets.UTF_8));
    assertThat(isdn.getSubAddress()).isEqualTo("bar");
    assertThat(isdn.getSubAddress(false)).isEqualTo("bar");
    assertThat(isdn.getSubAddressAsByteArray())
        .containsExactly("bar".getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("150862028003217 004");
    ISDNRecord isdn = new ISDNRecord();
    isdn.rdataFromString(t, null);
    assertThat(isdn.getAddress()).isEqualTo("150862028003217");
    assertThat(isdn.getSubAddress()).isEqualTo("004");
  }
}
