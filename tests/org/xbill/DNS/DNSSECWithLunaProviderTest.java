package org.xbill.DNS;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import junit.framework.TestCase;

import org.xbill.DNS.DNSSEC.Algorithm;

import com.chrysalisits.crypto.LunaJCAProvider;
import com.chrysalisits.crypto.LunaTokenManager;
import com.chrysalisits.cryptox.LunaJCEProvider;

public class DNSSECWithLunaProviderTest extends TestCase {

	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	private static final String KEY_ALGORITHM = "RSA";
	int algorithm = Algorithm.RSASHA1;
	String partitionName = "dns";
	String partitionPassword = "xX0x-XXXX-XxXx-xXxX";
	LunaTokenManager tokenManager = LunaTokenManager.getInstance();
	String lunaJCEProvider = "LunaJCEProvider";
	String lunaJCAProvider = "LunaJCAProvider";
	byte[] toSign = "The quick brown fox jumped over the lazy dog.".getBytes();

	public void setUp() {
		Security.addProvider(new LunaJCEProvider());
		Security.addProvider(new LunaJCAProvider());
		tokenManager.Login(partitionName, partitionPassword);
	}

	public void tearDown() {
		tokenManager.Logout();
	}

	public void testSignHSM() throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, lunaJCAProvider);
		keyPairGenerator.initialize(512);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM, lunaJCAProvider);
		signer.initSign(keyPair.getPrivate());
		signer.update(toSign);
		byte[] signature = signer.sign();
		assertNotNull(signature);

		// verify the signature
		Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM, lunaJCAProvider);
		verifier.initVerify(keyPair.getPublic());
		verifier.update(toSign);
		boolean verify = verifier.verify(signature);
		assertTrue(verify);

	}

	public void testSignWithDNSSECAndHSM() throws Exception {

		// generate a signature
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, lunaJCAProvider);
		keyPairGenerator.initialize(512);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		byte[] signature = DNSSEC.sign(keyPair.getPrivate(), keyPair.getPublic(), algorithm, toSign, lunaJCAProvider);
		assertNotNull(signature);

		// verify the signature
		Signature verifier = Signature.getInstance(DNSSEC.algString(algorithm), lunaJCAProvider);
		verifier.initVerify(keyPair.getPublic());
		verifier.update(toSign);
		boolean verify = verifier.verify(signature);
		assertTrue(verify);
	}

	public void testSignWithDNSSECAndSoftware() throws Exception {

		// generate a signature
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGenerator.initialize(512);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		byte[] signature = DNSSEC.sign(keyPair.getPrivate(), keyPair.getPublic(), algorithm, toSign);
		assertNotNull(signature);

		// verify the signature
		Signature verifier = Signature.getInstance(DNSSEC.algString(algorithm));
		verifier.initVerify(keyPair.getPublic());
		verifier.update(toSign);
		boolean verify = verifier.verify(signature);
		assertTrue(verify);
	}
}
