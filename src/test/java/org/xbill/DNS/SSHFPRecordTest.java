// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.xbill.DNS.utils.base16;

class SSHFPRecordTest {
  @Test
  void rdataFromString() throws IOException {
    String fingerprint = "CAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE";
    Tokenizer t = new Tokenizer("2 1 " + fingerprint);
    SSHFPRecord sshfpRecord = new SSHFPRecord();
    sshfpRecord.rdataFromString(t, null);
    assertEquals(SSHFPRecord.Algorithm.DSA, sshfpRecord.getAlgorithm());
    assertEquals(SSHFPRecord.Digest.SHA1, sshfpRecord.getDigestType());
    assertArrayEquals(base16.fromString(fingerprint), sshfpRecord.getFingerPrint());
  }

  @ParameterizedTest
  @CsvSource({
    SSHFPRecord.Digest.SHA1 + "," + DigestLengths.SHA1,
    SSHFPRecord.Digest.SHA256 + "," + DigestLengths.SHA256,
    "3,4",
    "4,4",
    "255,4"
  })
  void validFingerprintLengths(int digestType, int length) throws IOException {
    byte[] fingerprint = new byte[length];
    SSHFPRecord sshfpRecord =
        (SSHFPRecord)
            Record.fromString(
                Name.root,
                Type.SSHFP,
                DClass.IN,
                3600,
                "1 " + digestType + " " + base16.toString(fingerprint),
                Name.root);
    assertEquals(digestType, sshfpRecord.getDigestType());
    assertArrayEquals(fingerprint, sshfpRecord.getFingerPrint());

    SSHFPRecord constructed =
        new SSHFPRecord(Name.root, DClass.IN, 3600, 1, digestType, fingerprint);
    assertArrayEquals(fingerprint, constructed.getFingerPrint());
  }

  @ParameterizedTest
  @CsvSource({
    SSHFPRecord.Digest.SHA1 + ",4",
    SSHFPRecord.Digest.SHA1 + ",19",
    SSHFPRecord.Digest.SHA1 + ",21",
    SSHFPRecord.Digest.SHA1 + ",32",
    SSHFPRecord.Digest.SHA256 + ",4",
    SSHFPRecord.Digest.SHA256 + ",20",
    SSHFPRecord.Digest.SHA256 + ",31",
    SSHFPRecord.Digest.SHA256 + ",33"
  })
  void rdataFromStringInvalidFingerprintLengths(int digestType, int length) {
    String rdata = "1 " + digestType + " " + base16.toString(new byte[length]);
    assertThatThrownBy(
            () -> Record.fromString(Name.root, Type.SSHFP, DClass.IN, 3600, rdata, Name.root))
        .isInstanceOf(TextParseException.class)
        .hasMessageMatching(".+Expected.+fingerprint bytes, got.+");
  }

  @ParameterizedTest
  @CsvSource({
    SSHFPRecord.Digest.SHA1 + ",4",
    SSHFPRecord.Digest.SHA1 + ",19",
    SSHFPRecord.Digest.SHA1 + ",21",
    SSHFPRecord.Digest.SHA1 + ",32",
    SSHFPRecord.Digest.SHA256 + ",4",
    SSHFPRecord.Digest.SHA256 + ",20",
    SSHFPRecord.Digest.SHA256 + ",31",
    SSHFPRecord.Digest.SHA256 + ",33"
  })
  void rrFromWireInvalidFingerprintLengths(int digestType, int length) {
    DNSOutput rr = new DNSOutput();
    rr.writeByteArray(
        Record.newRecord(Name.root, Type.SSHFP, DClass.IN, 3600).toWire(Section.ANSWER));
    int lengthPos = rr.current() - 2;
    rr.writeU8(1);
    rr.writeU8(digestType);
    rr.writeByteArray(new byte[length]);
    rr.writeU16At(2 + length, lengthPos);
    assertThatThrownBy(() -> Record.fromWire(rr.toByteArray(), Section.ANSWER))
        .isInstanceOf(WireParseException.class)
        .hasMessageMatching("Expected.+fingerprint bytes, got.+");
  }

  @ParameterizedTest
  @CsvSource({
    SSHFPRecord.Digest.SHA1 + ",0",
    SSHFPRecord.Digest.SHA1 + ",4",
    SSHFPRecord.Digest.SHA1 + ",19",
    SSHFPRecord.Digest.SHA1 + ",21",
    SSHFPRecord.Digest.SHA1 + ",32",
    SSHFPRecord.Digest.SHA256 + ",0",
    SSHFPRecord.Digest.SHA256 + ",4",
    SSHFPRecord.Digest.SHA256 + ",20",
    SSHFPRecord.Digest.SHA256 + ",31",
    SSHFPRecord.Digest.SHA256 + ",33"
  })
  void constructorInvalidFingerprintLengths(int digestType, int length) {
    assertThatThrownBy(
            () -> new SSHFPRecord(Name.root, DClass.IN, 3600, 1, digestType, new byte[length]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageMatching("Expected.+fingerprint bytes, got.+");
  }
}
