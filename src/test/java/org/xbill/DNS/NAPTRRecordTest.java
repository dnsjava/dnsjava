// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class NAPTRRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t =
        new Tokenizer("100  50  \"s\"    \"http+N2L+N2C+N2R\"  \"!a\\\\!!b!i\"   www.example.com.");
    NAPTRRecord naptr = new NAPTRRecord();
    naptr.rdataFromString(t, null);
    assertThat(naptr.getOrder()).isEqualTo(100);
    assertThat(naptr.getPreference()).isEqualTo(50);
    assertThat(naptr.getFlags()).isEqualTo("s");
    assertThat(naptr.getService()).isEqualTo("http+N2L+N2C+N2R");
    assertThat(naptr.getService(false)).isEqualTo("http+N2L+N2C+N2R");
    assertThat(naptr.getServiceAsByteArray())
        .containsExactly("http+N2L+N2C+N2R".getBytes(StandardCharsets.UTF_8));
    assertThat(naptr.getRegexp()).isEqualTo("!a\\\\!!b!i");
    assertThat(naptr.getRegexp(false)).isEqualTo("!a\\!!b!i");
    assertThat(naptr.getRegexpAsByteArray())
        .containsExactly("!a\\!!b!i".getBytes(StandardCharsets.UTF_8));
    assertThat(naptr.getReplacement()).isEqualTo(Name.fromConstantString("www.example.com."));
  }
}
