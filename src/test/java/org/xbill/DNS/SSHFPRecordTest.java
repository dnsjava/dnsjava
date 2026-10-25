// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
    assertThat(sshfpRecord.getAlgorithm()).isEqualTo(SSHFPRecord.Algorithm.DSA);
    assertThat(sshfpRecord.getDigestType()).isEqualTo(SSHFPRecord.Digest.SHA1);
    assertThat(sshfpRecord.getFingerPrint()).containsExactly(base16.fromString(fingerprint));
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
    assertThat(sshfpRecord.getDigestType()).isEqualTo(digestType);
    assertThat(sshfpRecord.getFingerPrint()).containsExactly(fingerprint);

    SSHFPRecord constructed =
        new SSHFPRecord(Name.root, DClass.IN, 3600, 1, digestType, fingerprint);
    assertThat(constructed.getFingerPrint()).containsExactly(fingerprint);
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

  @Test
  void emptyFingerprintRoundtrip() throws IOException {
    SSHFPRecord sshfpRecord = new SSHFPRecord(Name.root, DClass.IN, 0, 123, 255, new byte[0]);
    assertThat(sshfpRecord.getFingerPrint()).isEmpty();
    String rr = sshfpRecord.rrToString();
    assertThat(rr).isEqualTo("123 255 \"\"");
    sshfpRecord = new SSHFPRecord();
    sshfpRecord.rdataFromString(new Tokenizer(rr), Name.root);
    assertThat(sshfpRecord.getAlgorithm()).isEqualTo(123);
    assertThat(sshfpRecord.getDigestType()).isEqualTo(255);
    assertThat(sshfpRecord.getFingerPrint()).isEmpty();
  }
}
