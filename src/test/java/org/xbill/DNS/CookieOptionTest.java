// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.IOException;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;

class CookieOptionTest {

  @Test
  void constructorTests() {
    byte[] sevenBytes = base16.fromString("20212223242526");
    byte[] eightBytes = base16.fromString("3031323334353637");
    byte[] eightBytes2 = base16.fromString("A0A1A2A3A4A5A6A7");
    byte[] nineBytes = base16.fromString("404142434445565748");
    byte[] thirtyTwoBytes =
        base16.fromString("505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F");
    byte[] thirtyThreeBytes =
        base16.fromString("707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F90");

    CookieOption option = new CookieOption(eightBytes);
    assertThat(option.getClientCookie()).containsExactly(eightBytes);
    assertThat(option.getServerCookie()).isNotPresent();
    new CookieOption(eightBytes, null);

    option = new CookieOption(eightBytes, null);
    assertThat(option.getClientCookie()).containsExactly(eightBytes);
    assertThat(option.getServerCookie()).isNotPresent();

    option = new CookieOption(eightBytes, eightBytes2);
    Optional<byte[]> serverCookie = option.getServerCookie();
    assertThat(serverCookie).isPresent();
    assertThat(serverCookie.get()).containsExactly(eightBytes2);

    option = new CookieOption(eightBytes, thirtyTwoBytes);
    serverCookie = option.getServerCookie();
    assertThat(serverCookie).isPresent();
    assertThat(serverCookie.get()).containsExactly(thirtyTwoBytes);

    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new CookieOption(sevenBytes));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new CookieOption(nineBytes));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new CookieOption(eightBytes, sevenBytes));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new CookieOption(eightBytes, thirtyThreeBytes));
  }

  @Test
  void wireTests() throws IOException {
    byte[] clientOnlyCookieOption = base16.fromString("000A00081011121314151617");
    byte[] clientCookie1 = base16.fromString("1011121314151617");
    byte[] clientServerCookieOption =
        base16.fromString("000A0012202122232425262730313233343536373839");
    byte[] clientCookie2 = base16.fromString("2021222324252627");
    byte[] serverCookie2 = base16.fromString("30313233343536373839");
    byte[] validLength1 = base16.fromString("000A0010000102030405060708090A0B0C0D0E0F");
    byte[] validLength2 =
        base16.fromString(
            "000A0028000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");
    byte[] brokenLength1 = base16.fromString("000A000700010203040506");
    byte[] brokenLength2 = base16.fromString("000A000C000102030405060708090A0B");
    byte[] brokenLength3 = base16.fromString("000A000F000102030405060708090A0B0C0D0E");
    byte[] brokenLength4 =
        base16.fromString(
            "000A0029000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728");

    EDNSOption option = EDNSOption.fromWire(clientOnlyCookieOption);
    assertThat(option).isNotNull();
    assertThat(option.getClass()).isEqualTo(CookieOption.class);
    CookieOption cookieOption = (CookieOption) option;
    assertThat(cookieOption.getClientCookie()).containsExactly(clientCookie1);
    assertThat(cookieOption.getServerCookie()).isNotPresent();

    option = EDNSOption.fromWire(clientServerCookieOption);
    assertThat(option).isNotNull();
    assertThat(option.getClass()).isEqualTo(CookieOption.class);
    cookieOption = (CookieOption) option;
    assertThat(cookieOption.getClientCookie()).containsExactly(clientCookie2);
    assertThat(cookieOption.getServerCookie()).isPresent();
    assertThat(cookieOption.getServerCookie().get()).containsExactly(serverCookie2);

    EDNSOption.fromWire(validLength1);
    EDNSOption.fromWire(validLength2);

    assertThatExceptionOfType(WireParseException.class)
        .isThrownBy(() -> EDNSOption.fromWire(brokenLength1));
    assertThatExceptionOfType(WireParseException.class)
        .isThrownBy(() -> EDNSOption.fromWire(brokenLength2));
    assertThatExceptionOfType(WireParseException.class)
        .isThrownBy(() -> EDNSOption.fromWire(brokenLength3));
    assertThatExceptionOfType(WireParseException.class)
        .isThrownBy(() -> EDNSOption.fromWire(brokenLength4));

    cookieOption = new CookieOption(clientCookie1);
    assertThat(cookieOption.toWire()).containsExactly(clientOnlyCookieOption);

    cookieOption = new CookieOption(clientCookie2, serverCookie2);
    assertThat(cookieOption.toWire()).containsExactly(clientServerCookieOption);
  }
}
