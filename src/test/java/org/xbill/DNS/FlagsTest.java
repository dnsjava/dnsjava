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

import org.junit.jupiter.api.Test;

class FlagsTest {
  @Test
  void string() {
    // a regular one
    assertThat(Flags.string(Flags.AA)).isEqualTo("aa");

    // one that doesn't exist
    assertThat(Flags.string(12).startsWith("flag")).isTrue();

    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> Flags.string(-1));

    //  (max is 0xF)
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> Flags.string(0x10));
  }

  @Test
  void value() {
    // regular one
    assertThat(Flags.value("cd")).isEqualTo(Flags.CD);

    // one thats undefined but within range
    assertThat(Flags.value("FLAG13")).isEqualTo(13);

    // one thats undefined but out of range
    assertThat(Flags.value("FLAG" + 0x10)).isEqualTo(-1);

    // something that unknown
    assertThat(Flags.value("THIS IS DEFINITELY UNKNOWN")).isEqualTo(-1);

    // empty string
    assertThat(Flags.value("")).isEqualTo(-1);
  }

  @Test
  void isFlag() {
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> Flags.isFlag(-1));
    assertThat(Flags.isFlag(0)).isTrue();
    assertThat(Flags.isFlag(1)).isFalse(); // opcode
    assertThat(Flags.isFlag(2)).isFalse();
    assertThat(Flags.isFlag(3)).isFalse();
    assertThat(Flags.isFlag(4)).isFalse();
    assertThat(Flags.isFlag(5)).isTrue();
    assertThat(Flags.isFlag(6)).isTrue();
    assertThat(Flags.isFlag(7)).isTrue();
    assertThat(Flags.isFlag(8)).isTrue();
    assertThat(Flags.isFlag(9)).isTrue();
    assertThat(Flags.isFlag(10)).isTrue();
    assertThat(Flags.isFlag(11)).isTrue();
    assertThat(Flags.isFlag(12)).isFalse();
    assertThat(Flags.isFlag(13)).isFalse();
    assertThat(Flags.isFlag(14)).isFalse();
    assertThat(Flags.isFlag(14)).isFalse();
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> Flags.isFlag(16));
  }
}
