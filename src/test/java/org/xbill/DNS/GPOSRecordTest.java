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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GPOSRecordTest {
  @Test
  void ctor_0arg() {
    GPOSRecord gr = new GPOSRecord();
    assertNull(gr.getName());
    assertEquals(0, gr.getType());
    assertEquals(0, gr.getDClass());
    assertEquals(0, gr.getTTL());
  }

  static class Test_Ctor_6arg_doubles {
    private Name m_n;
    private long m_ttl;
    private double m_lat, m_long, m_alt;

    @BeforeEach
    void setUp() throws TextParseException {
      m_n = Name.fromString("The.Name.");
      m_ttl = 0xABCDL;
      m_lat = -10.43;
      m_long = 76.12;
      m_alt = 100.101;
    }

    @Test
    void basic() {
      GPOSRecord gr = new GPOSRecord(m_n, DClass.IN, m_ttl, m_long, m_lat, m_alt);
      assertEquals(m_n, gr.getName());
      assertEquals(DClass.IN, gr.getDClass());
      assertEquals(Type.GPOS, gr.getType());
      assertEquals(m_ttl, gr.getTTL());
      assertEquals(m_long, gr.getLongitude());
      assertEquals(m_lat, gr.getLatitude());
      assertEquals(m_alt, gr.getAltitude());
      assertEquals(Double.toString(m_long), gr.getLongitudeString());
      assertEquals(Double.toString(m_lat), gr.getLatitudeString());
      assertEquals(Double.toString(m_alt), gr.getAltitudeString());
    }

    @Test
    void toosmall_longitude() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new GPOSRecord(m_n, DClass.IN, m_ttl, -90.001, m_lat, m_alt));
    }

    @Test
    void toobig_longitude() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new GPOSRecord(m_n, DClass.IN, m_ttl, 90.001, m_lat, m_alt));
    }

    @Test
    void toosmall_latitude() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new GPOSRecord(m_n, DClass.IN, m_ttl, m_long, -180.001, m_alt));
    }

    @Test
    void toobig_latitude() {
      assertThrows(
          IllegalArgumentException.class,
          () -> new GPOSRecord(m_n, DClass.IN, m_ttl, m_long, 180.001, m_alt));
    }

    @Test
    void invalid_string() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new GPOSRecord(
                  m_n,
                  DClass.IN,
                  m_ttl,
                  Double.toString(m_long),
                  "120.\\00ABC",
                  Double.toString(m_alt)));
    }
  }

  static class Test_Ctor_6arg_Strings {
    private Name m_n;
    private long m_ttl;
    private double m_lat, m_long, m_alt;

    @BeforeEach
    void setUp() throws TextParseException {
      m_n = Name.fromString("The.Name.");
      m_ttl = 0xABCDL;
      m_lat = -10.43;
      m_long = 76.12;
      m_alt = 100.101;
    }

    @Test
    void basic() {
      GPOSRecord gr =
          new GPOSRecord(
              m_n,
              DClass.IN,
              m_ttl,
              Double.toString(m_long),
              Double.toString(m_lat),
              Double.toString(m_alt));
      assertEquals(m_n, gr.getName());
      assertEquals(DClass.IN, gr.getDClass());
      assertEquals(Type.GPOS, gr.getType());
      assertEquals(m_ttl, gr.getTTL());
      assertEquals(m_long, gr.getLongitude());
      assertEquals(m_lat, gr.getLatitude());
      assertEquals(m_alt, gr.getAltitude());
      assertEquals(Double.toString(m_long), gr.getLongitudeString());
      assertEquals(Double.toString(m_lat), gr.getLatitudeString());
      assertEquals(Double.toString(m_alt), gr.getAltitudeString());
    }

    @Test
    void toosmall_longitude() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new GPOSRecord(
                  m_n,
                  DClass.IN,
                  m_ttl,
                  "-90.001",
                  Double.toString(m_lat),
                  Double.toString(m_alt)));
    }

    @Test
    void toobig_longitude() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new GPOSRecord(
                  m_n, DClass.IN, m_ttl, "90.001", Double.toString(m_lat), Double.toString(m_alt)));
    }

    @Test
    void toosmall_latitude() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new GPOSRecord(
                  m_n,
                  DClass.IN,
                  m_ttl,
                  Double.toString(m_long),
                  "-180.001",
                  Double.toString(m_alt)));
    }

    @Test
    void toobig_latitude() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new GPOSRecord(
                  m_n,
                  DClass.IN,
                  m_ttl,
                  Double.toString(m_long),
                  "180.001",
                  Double.toString(m_alt)));
    }
  }

  static class Test_rrFromWire {
    @Test
    void basic() throws IOException {
      byte[] raw =
          new byte[] {
            5, '-', '8', '.', '1', '2', 6, '1', '2', '3', '.', '0', '7', 3, '0', '.', '0'
          };
      DNSInput in = new DNSInput(raw);

      GPOSRecord gr = new GPOSRecord();
      gr.rrFromWire(in);
      assertEquals(-8.12, gr.getLongitude());
      assertEquals(123.07, gr.getLatitude());
      assertEquals(0.0, gr.getAltitude());
    }

    @Test
    void longitude_toosmall() {
      byte[] raw =
          new byte[] {
            5, '-', '9', '5', '.', '0', 6, '1', '2', '3', '.', '0', '7', 3, '0', '.', '0'
          };
      DNSInput in = new DNSInput(raw);

      GPOSRecord gr = new GPOSRecord();
      assertThrows(WireParseException.class, () -> gr.rrFromWire(in));
    }

    @Test
    void longitude_toobig() {
      byte[] raw =
          new byte[] {
            5, '1', '8', '5', '.', '0', 6, '1', '2', '3', '.', '0', '7', 3, '0', '.', '0'
          };
      DNSInput in = new DNSInput(raw);

      GPOSRecord gr = new GPOSRecord();
      assertThrows(WireParseException.class, () -> gr.rrFromWire(in));
    }

    @Test
    void latitude_toosmall() {
      byte[] raw =
          new byte[] {
            5, '-', '8', '5', '.', '0', 6, '-', '1', '9', '0', '.', '0', 3, '0', '.', '0'
          };
      DNSInput in = new DNSInput(raw);

      GPOSRecord gr = new GPOSRecord();
      assertThrows(WireParseException.class, () -> gr.rrFromWire(in));
    }

    @Test
    void latitude_toobig() {
      byte[] raw =
          new byte[] {
            5, '-', '8', '5', '.', '0', 6, '2', '1', '9', '0', '.', '0', 3, '0', '.', '0'
          };
      DNSInput in = new DNSInput(raw);

      GPOSRecord gr = new GPOSRecord();
      assertThrows(WireParseException.class, () -> gr.rrFromWire(in));
    }
  }

  static class Test_rdataFromString {
    @Test
    void basic() throws IOException {
      Tokenizer t = new Tokenizer("10.45 171.121212 1010787");

      GPOSRecord gr = new GPOSRecord();
      gr.rdataFromString(t, null);
      assertEquals(10.45, gr.getLongitude());
      assertEquals(171.121212, gr.getLatitude());
      assertEquals(1010787, gr.getAltitude());
    }

    @Test
    void longitude_toosmall() {
      Tokenizer t = new Tokenizer("-100.390 171.121212 1010787");

      GPOSRecord gr = new GPOSRecord();
      assertThrows(IOException.class, () -> gr.rdataFromString(t, null));
    }

    @Test
    void longitude_toobig() {
      Tokenizer t = new Tokenizer("90.00001 171.121212 1010787");

      GPOSRecord gr = new GPOSRecord();
      assertThrows(IOException.class, () -> gr.rdataFromString(t, null));
    }

    @Test
    void latitude_toosmall() {
      Tokenizer t = new Tokenizer("0.0 -180.01 1010787");

      GPOSRecord gr = new GPOSRecord();
      assertThrows(IOException.class, () -> gr.rdataFromString(t, null));
    }

    @Test
    void latitude_toobig() {
      Tokenizer t = new Tokenizer("0.0 180.01 1010787");

      GPOSRecord gr = new GPOSRecord();
      assertThrows(IOException.class, () -> gr.rdataFromString(t, null));
    }

    @Test
    void invalid_string() throws IOException {
      Tokenizer t = new Tokenizer("1.0 2.0 \\435");
      try {
        GPOSRecord gr = new GPOSRecord();
        gr.rdataFromString(t, null);
      } catch (TextParseException e) {
      }
    }
  }

  @Test
  void rrToString() throws TextParseException {
    String exp = "\"10.45\" \"171.121212\" \"1010787.0\"";

    GPOSRecord gr =
        new GPOSRecord(Name.fromString("The.Name."), DClass.IN, 0x123, 10.45, 171.121212, 1010787);
    assertEquals(exp, gr.rrToString());
  }

  @Test
  void rrToWire() throws TextParseException {
    GPOSRecord gr =
        new GPOSRecord(Name.fromString("The.Name."), DClass.IN, 0x123, -10.45, 120.0, 111.0);

    byte[] exp =
        new byte[] {
          6, '-', '1', '0', '.', '4', '5', 5, '1', '2', '0', '.', '0', 5, '1', '1', '1', '.', '0'
        };

    DNSOutput out = new DNSOutput();
    gr.rrToWire(out, null, true);

    byte[] bar = out.toByteArray();

    assertEquals(exp.length, bar.length);
    for (int i = 0; i < exp.length; ++i) {
      assertEquals(exp[i], bar[i], "i=" + i);
    }
  }
}
