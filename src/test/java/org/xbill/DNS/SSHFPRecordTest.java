// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
    assertEquals(SSHFPRecord.Algorithm.DSS, sshfpRecord.getAlgorithm());
    assertEquals(SSHFPRecord.Digest.SHA1, sshfpRecord.getDigestType());
    assertArrayEquals(base16.fromString(fingerprint), sshfpRecord.getFingerPrint());
  }

  @ParameterizedTest
  @CsvSource({"1,20", "2,32", "3,4", "4,4", "255,4"})
  void validFingerprintLengths(int digestType, int length) throws IOException {
    byte[] fingerprint = new byte[length];
    SSHFPRecord record =
        (SSHFPRecord)
            Record.fromString(
                Name.root,
                Type.SSHFP,
                DClass.IN,
                3600,
                "1 " + digestType + " " + base16.toString(fingerprint),
                Name.root);
    assertEquals(digestType, record.getDigestType());
    assertArrayEquals(fingerprint, record.getFingerPrint());

    SSHFPRecord constructed =
        new SSHFPRecord(Name.root, DClass.IN, 3600, 1, digestType, fingerprint);
    assertArrayEquals(fingerprint, constructed.getFingerPrint());
  }

  @ParameterizedTest
  @CsvSource({"1,4", "1,19", "1,21", "1,32", "2,4", "2,20", "2,31", "2,33"})
  void rdataFromStringInvalidFingerprintLengths(int digestType, int length) {
    String rdata = "1 " + digestType + " " + base16.toString(new byte[length]);
    assertThrows(
        TextParseException.class,
        () -> Record.fromString(Name.root, Type.SSHFP, DClass.IN, 3600, rdata, Name.root));
  }

  @ParameterizedTest
  @CsvSource({"1,0", "1,4", "1,19", "1,21", "1,32", "2,0", "2,4", "2,20", "2,31", "2,33"})
  void constructorInvalidFingerprintLengths(int digestType, int length) {
    assertThrows(
        IllegalArgumentException.class,
        () -> new SSHFPRecord(Name.root, DClass.IN, 3600, 1, digestType, new byte[length]));
  }
}
