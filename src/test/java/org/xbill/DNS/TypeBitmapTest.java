// SPDX-License-Identifier: BSD-3-Clause
// -*- Java -*-
//
// Copyright (c) 2011, org.xbill.DNS
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class TypeBitmapTest {
  @Test
  void empty() {
    TypeBitmap typeBitmap = new TypeBitmap(new int[] {});
    assertEquals("", typeBitmap.toString());
  }

  @Test
  void typeA() {
    TypeBitmap typeBitmap = new TypeBitmap(new int[] {Type.A});
    assertEquals("A", typeBitmap.toString());
  }

  @Test
  void typeNSandSOA() {
    TypeBitmap typeBitmap = new TypeBitmap(new int[] {Type.NS, Type.SOA});
    assertEquals("NS SOA", typeBitmap.toString());
  }

  @Test
  void typeNSandSOAArray() {
    int[] typeArray = new int[] {Type.NS, Type.SOA};
    TypeBitmap typeBitmap = new TypeBitmap(typeArray);
    assertArrayEquals(typeArray, typeBitmap.toArray());
  }

  @Test
  void typeAAndSOAToWire() {
    int[] typeArray = new int[] {Type.A, Type.SOA};
    TypeBitmap typeBitmap = new TypeBitmap(typeArray);
    DNSOutput out = new DNSOutput();
    typeBitmap.toWire(out);
    assertArrayEquals(new byte[] {0, 1, 0b0100_0010}, out.toByteArray());
  }

  @Test
  void typeAandNSEC3ToWireAndBack() throws WireParseException {
    int[] typeArray = new int[] {Type.A, Type.NSEC3};
    byte[] wire =
        new byte[] {
          // block
          0,
          // size
          7,
          // 0-7
          0b0100_0000,
          // 8-15,
          0,
          // 16-23,
          0,
          // 24-31,
          0,
          // 32-39
          0,
          // 40-47
          0,
          // 48-55
          0b0010_0000
        };

    // Test serialization
    TypeBitmap typeBitmapOut = new TypeBitmap(typeArray);
    DNSOutput out = new DNSOutput();
    typeBitmapOut.toWire(out);
    assertArrayEquals(wire, out.toByteArray());

    // Test parsing
    DNSInput in = new DNSInput(wire);
    TypeBitmap typeBitmapIn = new TypeBitmap(in);
    assertArrayEquals(typeArray, typeBitmapIn.toArray());
  }
}
