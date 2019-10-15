package org.xbill.DNS;

import java.util.Optional;

import java.time.Duration;

import java.io.IOException;

import org.xbill.DNS.utils.base16;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CookieOptionTest {


  @Test
  void constructorTests() {
    byte[] sevenBytes = base16.fromString("20212223242526");
    byte[] eightBytes = base16.fromString("3031323334353637");
    byte[] eightBytes2 = base16.fromString("A0A1A2A3A4A5A6A7");
    byte[] nineBytes = base16.fromString("404142434445565748");
    byte[] thirtyTwoBytes = base16.fromString(
     "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F");
    byte[] thirtyThreeBytes = base16.fromString(
     "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90");

    CookieOption option = new CookieOption(eightBytes);
    assertArrayEquals(eightBytes, option.getClientCookie());
    assertFalse(option.getServerCookie().isPresent());
    new CookieOption(eightBytes, Optional.empty());

    option = new CookieOption(eightBytes, Optional.empty());
    assertArrayEquals(eightBytes, option.getClientCookie());
    assertFalse(option.getServerCookie().isPresent());

    option = new CookieOption(eightBytes, Optional.of(eightBytes2));
    Optional<byte[]> serverCookie = option.getServerCookie();
    assertTrue(serverCookie.isPresent());
    assertArrayEquals(eightBytes2, serverCookie.get());

    option = new CookieOption(eightBytes, Optional.of(thirtyTwoBytes));
    serverCookie = option.getServerCookie();
    assertTrue(serverCookie.isPresent());
    assertArrayEquals(thirtyTwoBytes, serverCookie.get());

    assertThrows(IllegalArgumentException.class, () -> new CookieOption(sevenBytes));
    assertThrows(IllegalArgumentException.class, () -> new CookieOption(nineBytes));
    assertThrows(IllegalArgumentException.class, () -> new CookieOption(eightBytes, Optional.of (sevenBytes)));
    assertThrows(IllegalArgumentException.class, () -> new CookieOption(eightBytes, Optional.of (thirtyThreeBytes)));
  }

  @Test
  void wireTests() throws IOException {
    byte[] clientOnlyCookieOption = base16.fromString("000A00081011121314151617");
    byte[] clientCookie1 = base16.fromString("1011121314151617");
    byte[] clientServerCookieOption = base16.fromString("000A0012202122232425262730313233343536373839");
    byte[] clientCookie2 = base16.fromString("2021222324252627");
    byte[] serverCookie2 = base16.fromString("30313233343536373839");
    byte[] validLength1 = base16.fromString("000A0010000102030405060708090A0B0C0D0E0F");
    byte[] validLength2 = base16.fromString("000A0028000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");
    byte[] brokenLength1 = base16.fromString("000A000700010203040506");
    byte[] brokenLength2 = base16.fromString("000A000C000102030405060708090A0B");
    byte[] brokenLength3 = base16.fromString("000A000F000102030405060708090A0B0C0D0E");
    byte[] brokenLength4 = base16.fromString("000A0029000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728");

    EDNSOption option = EDNSOption.fromWire(clientOnlyCookieOption);
    assertNotNull(option);
    assertEquals(CookieOption.class, option.getClass());
    CookieOption cookieOption = (CookieOption) option;
    assertArrayEquals(clientCookie1, cookieOption.getClientCookie());
    assertFalse(cookieOption.getServerCookie().isPresent());

    option = EDNSOption.fromWire(clientServerCookieOption);
    assertNotNull(option);
    assertEquals(CookieOption.class, option.getClass());
    cookieOption = (CookieOption) option;
    assertArrayEquals(clientCookie2, cookieOption.getClientCookie());
    assertTrue(cookieOption.getServerCookie().isPresent());
    assertArrayEquals(serverCookie2, cookieOption.getServerCookie().get());

    EDNSOption.fromWire(validLength1);
    EDNSOption.fromWire(validLength2);

    assertThrows(WireParseException.class, () -> EDNSOption.fromWire(brokenLength1));
    assertThrows(WireParseException.class, () -> EDNSOption.fromWire(brokenLength2));
    assertThrows(WireParseException.class, () -> EDNSOption.fromWire(brokenLength3));
    assertThrows(WireParseException.class, () -> EDNSOption.fromWire(brokenLength4));

    cookieOption = new CookieOption(clientCookie1);
    assertArrayEquals(clientOnlyCookieOption, cookieOption.toWire());

    cookieOption = new CookieOption(clientCookie2, Optional.of(serverCookie2));
    assertArrayEquals(clientServerCookieOption, cookieOption.toWire());
  }
}

