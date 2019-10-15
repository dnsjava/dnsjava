package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

class TcpKeepaliveOptionTest {

  @Test
  void constructorTests() {
    assertFalse(new TcpKeepaliveOption().getTimeout().isPresent());
    assertEquals(100, new TcpKeepaliveOption(100).getTimeout().getAsInt());
    assertThrows(IllegalArgumentException.class, () -> new TcpKeepaliveOption(-1));
    assertThrows(IllegalArgumentException.class, () -> new TcpKeepaliveOption(65536));
    assertEquals(200, new TcpKeepaliveOption(Duration.ofSeconds(20)).getTimeout().getAsInt());
    assertEquals(
        Duration.ofSeconds(30),
        new TcpKeepaliveOption(Duration.ofSeconds(30)).getTimeoutDuration().get());
    assertEquals(
        15,
        new TcpKeepaliveOption(Duration.ofSeconds(1, 599_999_999))
            .getTimeout()
            .getAsInt()); // round down test
    assertThrows(
        IllegalArgumentException.class, () -> new TcpKeepaliveOption(Duration.ofMillis(-1)));
    assertThrows(
        IllegalArgumentException.class,
        () -> new TcpKeepaliveOption(Duration.ofHours(2))); // 2h > 6553.5 seconds
  }

  @Test
  void wireTests() throws IOException {
    byte[] emptyTimeout = base16.fromString("000B0000");
    byte[] thirtySecsTimeout = base16.fromString("000B0002012C");
    byte[] maxTimeout = base16.fromString("000B0002FFFF");
    byte[] brokenLengthTimeout1 = base16.fromString("000B0001AA");
    byte[] brokenLengthTimeout2 = base16.fromString("000B0005AABBCCDDEE");

    EDNSOption option = EDNSOption.fromWire(emptyTimeout);
    assertNotNull(option);
    assertEquals(TcpKeepaliveOption.class, option.getClass());
    assertFalse(((TcpKeepaliveOption) option).getTimeout().isPresent());

    option = EDNSOption.fromWire(thirtySecsTimeout);
    assertNotNull(option);
    assertEquals(TcpKeepaliveOption.class, option.getClass());
    assertEquals(300, ((TcpKeepaliveOption) option).getTimeout().getAsInt());

    option = EDNSOption.fromWire(maxTimeout);
    assertNotNull(option);
    assertEquals(TcpKeepaliveOption.class, option.getClass());
    assertEquals(65535, ((TcpKeepaliveOption) option).getTimeout().getAsInt());

    assertThrows(WireParseException.class, () -> EDNSOption.fromWire(brokenLengthTimeout1));
    assertThrows(WireParseException.class, () -> EDNSOption.fromWire(brokenLengthTimeout2));

    assertArrayEquals(emptyTimeout, new TcpKeepaliveOption().toWire());
    assertArrayEquals(thirtySecsTimeout, new TcpKeepaliveOption(300).toWire());
    assertArrayEquals(maxTimeout, new TcpKeepaliveOption(65535).toWire());
  }
}
