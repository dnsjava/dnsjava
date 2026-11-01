// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

public class TXTRecordTest {
  @Test
  void encodingFromString() throws IOException {
    Record r = Record.fromString(Name.root, Type.TXT, DClass.IN, 0, "caf\\233", Name.root);
    assertThat(r.rdataToString()).isEqualTo("caf\\233");
  }

  @Test
  void encodingCtor() {
    // u009e -> Latin Small Letter E with Acute
    Record r = new TXTRecord(Name.root, Type.TXT, DClass.IN, "caf\u00e9");
    // As UTF-8: 0xC3 0xA9 (two bytes, because e acute is beyond 0x7f)
    assertThat(r.rdataToString()).isEqualTo("caf\\195\\169");
  }

  @Test
  void quotingSemicolon() {
    // RFC 1035 Section 5.1: The comment starts with a ';' (semicolon).
    // ';' (semicolon) inside a string
    Record r = new TXTRecord(Name.root, DClass.IN, 0, "v=DMARC1;p=reject");
    assertThat(r.rdataToString()).isEqualTo("\"v=DMARC1;p=reject\"");
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "color=blue|color=blue|false",
        "equation=a=4|equation=a=4|false",
        "a`=a=true|a`=a=true|false",
        "a\\`=a=false|a\\\\`=a=false|false",
        "`==\\=|`==\\\\=|false",
        "string=\"Cat\"|string=\\\"Cat\\\"|false",
        "string2=``abc``|string2=``abc``|false",
        "novalue=|novalue=|false",
        "a b=c d|a b=c d|true",
        "abc` =123 |abc` =123 |true",
      },
      delimiter = '|',
      ignoreLeadingAndTrailingWhitespace = false)
  void rfc1464Examples(String raw, String expected, boolean quoted) throws IOException {
    TXTRecord r = new TXTRecord();
    DNSOutput out = new DNSOutput();
    out.writeCountedString(raw.getBytes(StandardCharsets.US_ASCII));
    r.rrFromWire(new DNSInput(out.toByteArray()));
    String quotes = quoted ? "\"" : "";
    assertThat(r.rrToString()).isEqualTo(quotes + expected + quotes);

    TXTRecord r2 = new TXTRecord();
    r2.rdataFromString(new Tokenizer(r.rrToString()), Name.root);
    assertThat(r2.getStringsAsByteArrays())
        .first()
        .isEqualTo(raw.getBytes(StandardCharsets.US_ASCII));
    assertThat(r2.getStrings(false)).first().isEqualTo(raw);
    assertThat(r2.getStrings(true)).first().isEqualTo(expected);
  }

  @Test
  void quotingMultipleStrings() {
    // RFC 1035 Section 5.1: The comment starts with a ';' (semicolon).
    // ';' (semicolon) inside a string
    Record r =
        new TXTRecord(
            Name.root,
            DClass.IN,
            0,
            Stream.of("v=DMARC1;p=reject", "v=spf1 example.com", "something")
                .collect(Collectors.toList()));
    assertThat(r.rdataToString())
        .isEqualTo("\"v=DMARC1;p=reject\" \"v=spf1 example.com\" something");
  }

  @Test
  void escapesQuotes() throws IOException {
    TXTRecord r = new TXTRecord(Name.root, DClass.IN, 0, "v=some \"weird\" value");
    assertThat(r.rdataToString()).isEqualTo("\"v=some \\\"weird\\\" value\"");
    TXTRecord r2 = new TXTRecord();
    r2.rdataFromString(new Tokenizer("\"v=some \\\"weird\\\" value\""), Name.root);
    assertThat(r2.getStrings(true)).first().isEqualTo("v=some \\\"weird\\\" value");
    assertThat(r2.getStrings(false)).first().isEqualTo("v=some \"weird\" value");
  }

  @Test
  void emptyWritesQuotes() {
    TXTRecord r = new TXTRecord(Name.root, DClass.IN, 0, "");
    assertThat(r.rrToString()).isEqualTo("\"\"");
  }

  @ParameterizedTest
  @ValueSource(strings = {"aa(bb", "aa)bb", "aa(bb)cc"})
  void quotingParentheses(String value) {
    // RFC 1035 Section 5.1: Parentheses are used to group data that crosses a line boundary.
    // '(' and/or ')' inside a string
    Record r = new TXTRecord(Name.root, DClass.IN, 0, value);
    assertThat(r.rdataToString()).isEqualTo("\"" + value + "\"");
  }
}
