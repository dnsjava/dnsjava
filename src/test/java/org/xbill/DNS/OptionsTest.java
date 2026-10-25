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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OptionsTest {
  @BeforeEach
  void setUp() {
    // reset the options table before each test
    Options.clear();
  }

  @Test
  void set_1arg() {
    Options.set("Option1");
    assertThat(Options.value("option1")).isEqualTo("true");

    Options.set("OPTION2");
    assertThat(Options.value("option1")).isEqualTo("true");
    assertThat(Options.value("OpTIOn2")).isEqualTo("true");

    Options.set("option2");
    assertThat(Options.value("option2")).isEqualTo("true");
  }

  @Test
  void set_2arg() {
    Options.set("OPTION1", "Value1");
    assertThat(Options.value("Option1")).isEqualTo("value1");

    Options.set("option2", "value2");
    assertThat(Options.value("Option1")).isEqualTo("value1");
    assertThat(Options.value("OPTION2")).isEqualTo("value2");

    Options.set("OPTION2", "value2b");
    assertThat(Options.value("Option1")).isEqualTo("value1");
    assertThat(Options.value("option2")).isEqualTo("value2b");
  }

  @Test
  void check() {
    assertThat(Options.check("No Options yet")).isFalse();

    Options.set("First Option");
    assertThat(Options.check("Not a valid option name")).isFalse();
    assertThat(Options.check("First Option")).isTrue();
    assertThat(Options.check("FIRST option")).isTrue();
  }

  @Test
  void unset() {
    // unset something non-existent
    Options.unset("Not an option Name");

    Options.set("Temporary Option");
    assertThat(Options.check("Temporary Option")).isTrue();
    Options.unset("Temporary Option");
    assertThat(Options.check("Temporary Option")).isFalse();

    Options.set("Temporary Option");
    assertThat(Options.check("Temporary Option")).isTrue();
    Options.unset("temporary option");
    assertThat(Options.check("Temporary Option")).isFalse();

    // unset something now that the table is non-null
    Options.unset("Still Not an Option Name");
  }

  @Test
  void value() {
    assertThat(Options.value("Table is Null")).isNull();

    Options.set("Testing Option");
    assertThat(Options.value("Not an Option Name")).isNull();

    assertThat(Options.value("Testing OPTION")).isEqualTo("true");
  }

  @Test
  void intValue() {
    assertThat(Options.intValue("Table is Null")).isEqualTo(-1);

    Options.set("A Boolean Option");
    Options.set("An Int Option", "13");
    Options.set("Not An Int Option", "NotAnInt");
    Options.set("A Negative Int Value", "-1000");

    assertThat(Options.intValue("A Boolean Option")).isEqualTo(-1);
    assertThat(Options.intValue("Not an Option NAME")).isEqualTo(-1);
    assertThat(Options.intValue("an int option")).isEqualTo(13);
    assertThat(Options.intValue("NOT an INT option")).isEqualTo(-1);
    assertThat(Options.intValue("A negative int Value")).isEqualTo(-1);
  }

  @Test
  void systemProperty() {
    System.setProperty(
        "dnsjava.options", "booleanOption,valuedOption1=10,valuedOption2=NotAnInteger");

    Options.refresh();

    assertThat(Options.check("booleanOPTION")).isTrue();
    assertThat(Options.check("booleanOption")).isTrue();
    assertThat(Options.check("valuedOption1")).isTrue();
    assertThat(Options.check("ValuedOption2")).isTrue();

    assertThat(Options.value("booleanOption")).isEqualTo("true");
    assertThat(Options.intValue("BOOLEANOPTION")).isEqualTo(-1);
    assertThat(Options.value("valuedOption1")).isEqualTo("10");
    assertThat(Options.intValue("valuedOption1")).isEqualTo(10);
    assertThat(Options.value("VALUEDOPTION2")).isEqualTo("notaninteger");
    assertThat(Options.intValue("valuedOption2")).isEqualTo(-1);
  }
}
