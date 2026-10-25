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

class DClassTest {
  @Test
  void string() {
    // a regular one
    assertThat(DClass.string(DClass.IN)).isEqualTo("IN");

    // one with an alias
    assertThat(DClass.string(DClass.CH)).isEqualTo("CH");

    // one that doesn't exist
    assertThat(DClass.string(20)).startsWith("CLASS");

    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> DClass.string(-1));

    //  (max is 0xFFFF)
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> DClass.string(0x10000));
  }

  @Test
  void value() {
    // regular one
    assertThat(DClass.value("NONE")).isEqualTo(DClass.NONE);

    // one with alias
    assertThat(DClass.value("HS")).isEqualTo(DClass.HS);
    assertThat(DClass.value("HESIOD")).isEqualTo(DClass.HS);

    // one thats undefined but within range
    assertThat(DClass.value("CLASS21")).isEqualTo(21);

    // something that unknown
    assertThat(DClass.value("THIS IS DEFINITELY UNKNOWN")).isEqualTo(-1);

    // empty string
    assertThat(DClass.value("")).isEqualTo(-1);
  }
}
