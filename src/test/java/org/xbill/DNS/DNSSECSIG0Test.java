// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.Algorithm;

class DNSSECSIG0Test {

  private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
  private static final String KEY_ALGORITHM = "RSA";
  int algorithm = Algorithm.RSASHA1;
  byte[] toSign = "The quick brown fox jumped over the lazy dog.".getBytes();

  @BeforeEach
  void setUp() {}

  @AfterEach
  void tearDown() {}

  @Test
  void testSIG0() throws Exception {
    Name sig0zoneName = new Name("sig0.invalid.");
    Name sig0hostName = new Name("sometext.sig0.invalid.");

    KeyPairGenerator rsagen = KeyPairGenerator.getInstance("RSA");
    KeyPair rsapair = rsagen.generateKeyPair();
    PrivateKey privKey = rsapair.getPrivate();
    PublicKey pubKey = rsapair.getPublic();

    KEYRecord keyRecord =
        new KEYRecord(
            sig0zoneName,
            DClass.IN,
            0,
            KEYRecord.Flags.HOST,
            KEYRecord.Protocol.DNSSEC,
            DNSSEC.Algorithm.RSASHA1,
            pubKey);
    TXTRecord txtRecord = new TXTRecord(sig0hostName, DClass.IN, 0, "Hello World!");
    Update updateMessage = new Update(sig0zoneName);
    updateMessage.add(txtRecord);

    SIG0.signMessage(updateMessage, keyRecord, privKey, null);
    Message message = new Message(updateMessage.toWire());
    SIG0.verifyMessage(message, message.toWire(), keyRecord, null);
  }
}
