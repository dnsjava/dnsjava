// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.IOException;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

class TcpKeepaliveOptionTest {

  @Test
  void constructorTests() {
    assertThat(new TcpKeepaliveOption().getTimeout().isPresent()).isFalse();
    assertThat(new TcpKeepaliveOption(100).getTimeout().getAsInt()).isEqualTo(100);
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TcpKeepaliveOption(-1));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TcpKeepaliveOption(65536));
    assertThat(new TcpKeepaliveOption(Duration.ofSeconds(20)).getTimeout().getAsInt())
        .isEqualTo(200);
    assertThat(new TcpKeepaliveOption(Duration.ofSeconds(30)).getTimeoutDuration())
        .contains(Duration.ofSeconds(30));
    assertThat(new TcpKeepaliveOption(Duration.ofSeconds(1, 599_999_999)).getTimeout().getAsInt())
        .isEqualTo(15); // round down test
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TcpKeepaliveOption(Duration.ofMillis(-1)));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new TcpKeepaliveOption(Duration.ofHours(2))); // 2h > 6553.5 seconds
  }

  @Test
  void wireTests() throws IOException {
    byte[] emptyTimeout = base16.fromString("000B0000");
    byte[] thirtySecsTimeout = base16.fromString("000B0002012C");
    byte[] maxTimeout = base16.fromString("000B0002FFFF");
    byte[] brokenLengthTimeout1 = base16.fromString("000B0001AA");
    byte[] brokenLengthTimeout2 = base16.fromString("000B0005AABBCCDDEE");

    EDNSOption option = EDNSOption.fromWire(emptyTimeout);
    assertThat(option).isNotNull();
    assertThat(option.getClass()).isEqualTo(TcpKeepaliveOption.class);
    assertThat(((TcpKeepaliveOption) option).getTimeout().isPresent()).isFalse();

    option = EDNSOption.fromWire(thirtySecsTimeout);
    assertThat(option).isNotNull();
    assertThat(option.getClass()).isEqualTo(TcpKeepaliveOption.class);
    assertThat(((TcpKeepaliveOption) option).getTimeout().getAsInt()).isEqualTo(300);

    option = EDNSOption.fromWire(maxTimeout);
    assertThat(option).isNotNull();
    assertThat(option.getClass()).isEqualTo(TcpKeepaliveOption.class);
    assertThat(((TcpKeepaliveOption) option).getTimeout().getAsInt()).isEqualTo(65535);

    assertThatExceptionOfType(WireParseException.class)
        .isThrownBy(() -> EDNSOption.fromWire(brokenLengthTimeout1));
    assertThatExceptionOfType(WireParseException.class)
        .isThrownBy(() -> EDNSOption.fromWire(brokenLengthTimeout2));

    assertThat(new TcpKeepaliveOption().toWire()).containsExactly(emptyTimeout);
    assertThat(new TcpKeepaliveOption(300).toWire()).containsExactly(thirtySecsTimeout);
    assertThat(new TcpKeepaliveOption(65535).toWire()).containsExactly(maxTimeout);
  }
}
