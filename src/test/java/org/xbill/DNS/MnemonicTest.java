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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

// Mnemonic has package-level access.

class MnemonicTest {
  private Mnemonic m_mn;

  @BeforeEach
  void setUp() {
    m_mn = new Mnemonic(MnemonicTest.class.getName() + " UPPER", Mnemonic.CASE_UPPER);
  }

  @Test
  void no_maximum() {
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_mn.check(-1));
    assertThatCode(() -> m_mn.check(0)).doesNotThrowAnyException();
    assertThatCode(() -> m_mn.check(Integer.MAX_VALUE)).doesNotThrowAnyException();

    m_mn.setNumericAllowed(true);

    int val = m_mn.getValue("-2");
    assertThat(val).isEqualTo(-1);

    val = m_mn.getValue("0");
    assertThat(val).isZero();

    val = m_mn.getValue("" + Integer.MAX_VALUE);
    assertThat(val).isEqualTo(Integer.MAX_VALUE);
  }

  @Test
  void setMaximum() {
    m_mn.setMaximum(15);
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_mn.check(-1));
    assertThatCode(() -> m_mn.check(0)).doesNotThrowAnyException();
    assertThatCode(() -> m_mn.check(15)).doesNotThrowAnyException();
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_mn.check(16));

    // need numericok to exercise the usage of max in parseNumeric
    m_mn.setNumericAllowed(true);

    int val = m_mn.getValue("-2");
    assertThat(val).isEqualTo(-1);

    val = m_mn.getValue("0");
    assertThat(val).isZero();

    val = m_mn.getValue("15");
    assertThat(val).isEqualTo(15);

    val = m_mn.getValue("16");
    assertThat(val).isEqualTo(-1);
  }

  @Test
  void setPrefix() {
    final String prefix = "A mixed CASE Prefix".toUpperCase();
    m_mn.setPrefix(prefix);

    String out = m_mn.getText(10);
    assertThat(out).isEqualTo(prefix + "10");

    int i = m_mn.getValue(out);
    assertThat(i).isEqualTo(10);
  }

  @Test
  void basic_operation() {
    // setUp creates Mnemonic with CASE_UPPER
    m_mn.add(10, "Ten");
    m_mn.add(20, "Twenty");
    m_mn.addAlias(20, "Veinte");
    m_mn.add(30, "Thirty");

    String text = m_mn.getText(10);
    assertThat(text).isEqualTo("TEN");

    text = m_mn.getText(20);
    assertThat(text).isEqualTo("TWENTY");

    text = m_mn.getText(30);
    assertThat(text).isEqualTo("THIRTY");

    text = m_mn.getText(40);
    assertThat(text).isEqualTo("40");

    int value = m_mn.getValue("tEn");
    assertThat(value).isEqualTo(10);

    value = m_mn.getValue("twenty");
    assertThat(value).isEqualTo(20);

    value = m_mn.getValue("VeiNTe");
    assertThat(value).isEqualTo(20);

    value = m_mn.getValue("THIRTY");
    assertThat(value).isEqualTo(30);
  }

  @Test
  void basic_operation_lower() {
    m_mn = new Mnemonic(MnemonicTest.class.getName() + " LOWER", Mnemonic.CASE_LOWER);
    m_mn.add(10, "Ten");
    m_mn.add(20, "Twenty");
    m_mn.addAlias(20, "Veinte");
    m_mn.add(30, "Thirty");

    String text = m_mn.getText(10);
    assertThat(text).isEqualTo("ten");

    text = m_mn.getText(20);
    assertThat(text).isEqualTo("twenty");

    text = m_mn.getText(30);
    assertThat(text).isEqualTo("thirty");

    text = m_mn.getText(40);
    assertThat(text).isEqualTo("40");

    int value = m_mn.getValue("tEn");
    assertThat(value).isEqualTo(10);

    value = m_mn.getValue("twenty");
    assertThat(value).isEqualTo(20);

    value = m_mn.getValue("VeiNTe");
    assertThat(value).isEqualTo(20);

    value = m_mn.getValue("THIRTY");
    assertThat(value).isEqualTo(30);
  }

  @Test
  void basic_operation_sensitive() {
    m_mn = new Mnemonic(MnemonicTest.class.getName() + " SENSITIVE", Mnemonic.CASE_SENSITIVE);
    m_mn.add(10, "Ten");
    m_mn.add(20, "Twenty");
    m_mn.addAlias(20, "Veinte");
    m_mn.add(30, "Thirty");

    String text = m_mn.getText(10);
    assertThat(text).isEqualTo("Ten");

    text = m_mn.getText(20);
    assertThat(text).isEqualTo("Twenty");

    text = m_mn.getText(30);
    assertThat(text).isEqualTo("Thirty");

    text = m_mn.getText(40);
    assertThat(text).isEqualTo("40");

    int value = m_mn.getValue("Ten");
    assertThat(value).isEqualTo(10);

    value = m_mn.getValue("twenty");
    assertThat(value).isEqualTo(-1);

    value = m_mn.getValue("Twenty");
    assertThat(value).isEqualTo(20);

    value = m_mn.getValue("VEINTE");
    assertThat(value).isEqualTo(-1);

    value = m_mn.getValue("Veinte");
    assertThat(value).isEqualTo(20);

    value = m_mn.getValue("Thirty");
    assertThat(value).isEqualTo(30);
  }

  @Test
  void invalid_numeric() {
    m_mn.setNumericAllowed(true);
    int value = m_mn.getValue("Not-A-Number");
    assertThat(value).isEqualTo(-1);
  }

  @Test
  void addAll() {
    m_mn.add(10, "Ten");
    m_mn.add(20, "Twenty");

    Mnemonic mn2 = new Mnemonic("second test Mnemonic", Mnemonic.CASE_UPPER);
    mn2.add(20, "Twenty");
    mn2.addAlias(20, "Veinte");
    mn2.add(30, "Thirty");

    m_mn.addAll(mn2);

    String text = m_mn.getText(10);
    assertThat(text).isEqualTo("TEN");

    text = m_mn.getText(20);
    assertThat(text).isEqualTo("TWENTY");

    text = m_mn.getText(30);
    assertThat(text).isEqualTo("THIRTY");

    text = m_mn.getText(40);
    assertThat(text).isEqualTo("40");

    int value = m_mn.getValue("tEn");
    assertThat(value).isEqualTo(10);

    value = m_mn.getValue("twenty");
    assertThat(value).isEqualTo(20);

    value = m_mn.getValue("VeiNTe");
    assertThat(value).isEqualTo(20);

    value = m_mn.getValue("THIRTY");
    assertThat(value).isEqualTo(30);
  }

  @Test
  void remove() {
    m_mn.add(10, "Ten");
    m_mn.addAlias(10, "Diez");
    assertThat(m_mn.getValue("TEN")).isEqualTo(10);
    assertThat(m_mn.getValue("DIEZ")).isEqualTo(10);
    assertThat(m_mn.getText(10)).isEqualTo("TEN");

    m_mn.remove(10);
    assertThat(m_mn.getValue("TEN")).isEqualTo(-1);
    assertThat(m_mn.getValue("DIEZ")).isEqualTo(-1);
    assertThat(m_mn.getText(10)).isEqualTo("10");
  }

  @Test
  void removeAlias() {
    m_mn.add(10, "Ten");
    m_mn.addAlias(10, "Diez");
    assertThat(m_mn.getValue("TEN")).isEqualTo(10);
    assertThat(m_mn.getValue("DIEZ")).isEqualTo(10);

    m_mn.removeAlias("Diez");
    assertThat(m_mn.getValue("TEN")).isEqualTo(10);
    assertThat(m_mn.getValue("DIEZ")).isEqualTo(-1);
  }

  @Test
  void addAll_invalid() {
    Mnemonic mn2 = new Mnemonic("second test Mnemonic", Mnemonic.CASE_LOWER);
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m_mn.addAll(mn2));
  }
}
