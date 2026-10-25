// SPDX-License-Identifier: BSD-3-Clause
// -*- Java -*-
//
// Copyright (c) 2005, Matthew J. Rutherford <rutherfo@cs.colorado.edu>
// Copyright (c) 2005, University of Colorado at Boulder
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of the University of Colorado at Boulder nor the
//   names of its contributors may be used to endorse or promote
//   products derived from this software without specific prior written
//   permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TTLTest {
  private static final long S = 1;
  private static final long M = 60 * S;
  private static final long H = 60 * M;
  private static final long D = 24 * H;
  private static final long W = 7 * D;

  @Test
  void parseTTL() {
    assertThat(TTL.parseTTL("9876")).isEqualTo(9876);

    assertThat(TTL.parseTTL("0S")).isZero();
    assertThat(TTL.parseTTL("0M")).isZero();
    assertThat(TTL.parseTTL("0H")).isZero();
    assertThat(TTL.parseTTL("0D")).isZero();
    assertThat(TTL.parseTTL("0W")).isZero();

    assertThat(TTL.parseTTL("1s")).isEqualTo(S);
    assertThat(TTL.parseTTL("1m")).isEqualTo(M);
    assertThat(TTL.parseTTL("1h")).isEqualTo(H);
    assertThat(TTL.parseTTL("1d")).isEqualTo(D);
    assertThat(TTL.parseTTL("1w")).isEqualTo(W);

    assertThat(TTL.parseTTL("98S")).isEqualTo(98 * S);
    assertThat(TTL.parseTTL("76M")).isEqualTo(76 * M);
    assertThat(TTL.parseTTL("54H")).isEqualTo(54 * H);
    assertThat(TTL.parseTTL("32D")).isEqualTo(32 * D);
    assertThat(TTL.parseTTL("10W")).isEqualTo(10 * W);

    assertThat(TTL.parseTTL("98S11M1234H2D01W")).isEqualTo(98 * S + 11 * M + 1234 * H + 2 * D + W);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "S",
        "1h30",
        "10S4B",
        "1S4294967295S",
        "4294967296",
      })
  void parseTTL_invalid(String ttl) {
    assertThatThrownBy(() -> TTL.parseTTL(ttl)).isInstanceOf(NumberFormatException.class);
  }

  @Test
  void parseNullTtlIsInvalid() {
    assertThatThrownBy(() -> TTL.parseTTL(null)).isInstanceOf(NumberFormatException.class);
  }

  @Test
  void format() {
    assertThat(TTL.format(0)).isEqualTo("0S");
    assertThat(TTL.format(1)).isEqualTo("1S");
    assertThat(TTL.format(59)).isEqualTo("59S");
    assertThat(TTL.format(60)).isEqualTo("1M");
    assertThat(TTL.format(59 * M)).isEqualTo("59M");
    assertThat(TTL.format(M + 33)).isEqualTo("1M33S");
    assertThat(TTL.format(59 * M + 59 * S)).isEqualTo("59M59S");
    assertThat(TTL.format(H)).isEqualTo("1H");
    assertThat(TTL.format(10 * H + M + 21)).isEqualTo("10H1M21S");
    assertThat(TTL.format(23 * H + 59 * M + 59)).isEqualTo("23H59M59S");
    assertThat(TTL.format(D)).isEqualTo("1D");
    assertThat(TTL.format(4 * D + 18 * H + 45 * M + 30)).isEqualTo("4D18H45M30S");
    assertThat(TTL.format(6 * D + 23 * H + 59 * M + 59)).isEqualTo("6D23H59M59S");
    assertThat(TTL.format(W)).isEqualTo("1W");
    assertThat(TTL.format(10 * W + 4 * D + H + 21 * M + 29)).isEqualTo("10W4D1H21M29S");
    assertThat(TTL.format(0x7FFFFFFFL)).isEqualTo("3550W5D3H14M7S");
  }

  @Test
  void format_invalid() {
    assertThatExceptionOfType(InvalidTTLException.class).isThrownBy(() -> TTL.format(-1));

    assertThatExceptionOfType(InvalidTTLException.class).isThrownBy(() -> TTL.format(0x100000000L));
  }
}
