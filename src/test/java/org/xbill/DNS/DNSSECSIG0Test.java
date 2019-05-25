package org.xbill.DNS;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.DNSSEC.Algorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DNSSECSIG0Test {

	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	private static final String KEY_ALGORITHM = "RSA";
	int algorithm = Algorithm.RSASHA1;
	byte[] toSign = "The quick brown fox jumped over the lazy dog.".getBytes();

   @Before
   public void setUp() {
	}

   @After
   public void tearDown() {
	}

    @Test
	public void testSIG0() throws Exception {
		Name sig0zoneName = new Name("sig0.invalid.");
		Name sig0hostName = new Name("sometext.sig0.invalid.");

		KeyPairGenerator rsagen = KeyPairGenerator.getInstance("RSA");
		KeyPair rsapair = rsagen.generateKeyPair();
		PrivateKey privKey = rsapair.getPrivate();
		PublicKey pubKey = rsapair.getPublic();

		KEYRecord keyRecord = new KEYRecord(sig0zoneName, DClass.IN,
						    0, KEYRecord.Flags.HOST,
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
