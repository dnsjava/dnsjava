package org.xbill.DNS;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base16;
import org.xbill.DNS.utils.base64;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class MasterTest {

	@Test
	void nextRecord() throws IOException {
		Name exampleComName = Name.fromConstantString("example.com.");
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx1"))) {
			master.expandGenerate(false);
			Record rr = master.nextRecord();
			assertEquals(Type.SOA, rr.getType());
			rr = master.nextRecord();
			assertEquals(Type.NS, rr.getType());
			rr = master.nextRecord();
			assertEquals(Type.MX, rr.getType());

			rr = master.nextRecord();
			// test special '@' resolves name correctly
			assertEquals(exampleComName, rr.getName());

			rr = master.nextRecord();
			// test relative host become absolute
			assertEquals(Name.fromConstantString("mail3.example.com."), rr.getAdditionalName());

			rr = master.nextRecord();
			assertEquals(Type.A, rr.getType());

			rr = master.nextRecord();
			assertEquals(Type.AAAA, rr.getType());

			rr = master.nextRecord();
			assertEquals(Type.CNAME, rr.getType());

			rr = master.nextRecord();
			assertNull(rr);
			// $GENERATE directive is last in zonefile
			assertTrue(master.generators().hasNext());
		}
	}

	@Test
	void includeDirective() throws IOException, URISyntaxException {
		try (Master master = new Master(
			Paths.get(MasterTest.class.getResource("/zonefileIncludeDirective")
				.toURI()).toString())) {
			Record rr = master.nextRecord();
			assertEquals(Type.SOA, rr.getType());
		}
	}

	@Test
	void expandGenerated() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx1"))) {
			master.expandGenerate(true);
			// until we get to the generator directive, it's empty
			assertFalse(master.generators().hasNext());
			Record rr = skipTo(master, Type.PTR);
			assertTrue(master.generators().hasNext());
			assertEquals(Type.PTR, rr.getType());
			assertEquals(Name.fromConstantString("host-1.dsl.example.com."), ((PTRRecord) rr).getTarget());
		}
	}

	@Test
	void nullMXRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.MX);
			assertEquals(Type.MX, rr.getType());
			assertEquals(0, ((MXRecord) rr).getPriority());
			assertEquals(Name.fromConstantString("."), ((MXRecord) rr).getTarget());
		}
	}

	@Test
	void RPRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.RP);
			assertEquals(Type.RP, rr.getType());
			assertEquals(Name.fromConstantString("louie.trantor.umd.edu."), ((RPRecord) rr).getMailbox());
			assertEquals(Name.fromConstantString("LAM1.people.umd.edu."), ((RPRecord) rr).getTextDomain());
		}
	}

	@Test
	void HINFORecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.HINFO);
			assertEquals(Type.HINFO, rr.getType());
			assertEquals("NeXT", ((HINFORecord) rr).getCPU());
			assertEquals("UNIX", ((HINFORecord) rr).getOS());
		}
	}

	@Test
	void WKSRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.WKS);
			assertEquals(Type.WKS, rr.getType());
			assertNotNull(((WKSRecord) rr).getAddress());
			assertEquals(WKSRecord.Protocol.TCP, ((WKSRecord) rr).getProtocol());
			assertArrayEquals(new int[]{
				WKSRecord.Service.FTP,
				WKSRecord.Service.TELNET,
				WKSRecord.Service.SMTP}, ((WKSRecord) rr).getServices());
		}
	}

	@Test
	void ISDNRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.ISDN);
			assertEquals(Type.ISDN, rr.getType());
			assertEquals("150862028003217", ((ISDNRecord) rr).getAddress());
			assertEquals("004", ((ISDNRecord) rr).getSubAddress());
		}
	}

	@Test
	void LOCRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.LOC);
			assertEquals(Type.LOC, rr.getType());
			assertEquals(52.37, ((LOCRecord) rr).getLatitude(), 0.1);
			assertEquals(4.89, ((LOCRecord) rr).getLongitude(), 0.1);
			assertEquals(-2.0, ((LOCRecord) rr).getAltitude(), 0.1);
			assertEquals(10000.0, ((LOCRecord) rr).getHPrecision(), 0.1);
			assertEquals(10.0, ((LOCRecord) rr).getVPrecision(), 0.1);
		}
	}

	@Test
	void NSECRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.NSEC);
			assertEquals(Type.NSEC, rr.getType());
			assertEquals(Name.fromConstantString("host.example.com."), ((NSECRecord) rr).getNext());
			assertFalse(((NSECRecord) rr).hasType(-1));
		}
	}

	@Test
	void NSEC3Record() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.NSEC3);
			assertEquals(Type.NSEC3, rr.getType());
			assertEquals(NSEC3Record.Digest.SHA1, ((NSEC3Record) rr).getHashAlgorithm());
			assertEquals(NSEC3Record.Flags.OPT_OUT, ((NSEC3Record) rr).getFlags());
			assertNotNull(((NSEC3Record) rr).getSalt());

			rr = master.nextRecord();
			assertNull(((NSEC3Record) rr).getSalt());
		}
	}

	@Test
	void NSEC3PARAMRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.NSEC3PARAM);
			assertEquals(Type.NSEC3PARAM, rr.getType());
			assertEquals(NSEC3Record.Digest.SHA1, ((NSEC3PARAMRecord) rr).getHashAlgorithm());
			assertEquals(NSEC3Record.Flags.OPT_OUT, ((NSEC3PARAMRecord) rr).getFlags());
			assertNotNull(((NSEC3PARAMRecord) rr).getSalt());
		}
	}

	@Test
	void RRSIGRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.RRSIG);
			assertEquals(Type.RRSIG, rr.getType());
			assertEquals(10, ((RRSIGRecord) rr).getAlgorithm());
			assertEquals(31055, ((RRSIGRecord) rr).getFootprint());
			assertEquals(Name.fromConstantString("example.com."), ((RRSIGRecord) rr).getSigner());
			assertEquals(50, ((RRSIGRecord) rr).getTypeCovered());
			assertNotNull(((RRSIGRecord) rr).getExpire());
			assertNotNull(((RRSIGRecord) rr).getTimeSigned());
		}
	}

	@Test
	void SPFRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.SPF);
			assertEquals(Type.SPF, rr.getType());
			assertEquals(6, ((SPFRecord) rr).getStrings().size());
			assertEquals(6, ((SPFRecord) rr).getStringsAsByteArrays().size());
		}
	}

	@Test
	void SRVRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.SRV);
			assertEquals(Type.SRV, rr.getType());
			assertEquals(0, ((SRVRecord) rr).getPriority());
			assertEquals(5, ((SRVRecord) rr).getWeight());
			assertEquals(5060, ((SRVRecord) rr).getPort());
			assertEquals(Name.fromConstantString("sipserver.example.com."), ((SRVRecord) rr).getTarget());
			assertEquals(rr.getAdditionalName(), ((SRVRecord) rr).getTarget());
		}
	}

	@Test
	void CAARecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.CAA);
			assertEquals(Type.CAA, rr.getType());
			assertEquals("issue", ((CAARecord) rr).getTag());
			assertEquals("entrust.net", ((CAARecord) rr).getValue());
		}
	}

	@Test
	void DNSKEYRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.DNSKEY);
			assertEquals(Type.DNSKEY, rr.getType());
			assertEquals(256, ((DNSKEYRecord) rr).getFlags());
			assertEquals(3, ((DNSKEYRecord) rr).getProtocol());
			assertEquals(5, ((DNSKEYRecord) rr).getAlgorithm());
			assertEquals(60485, ((DNSKEYRecord) rr).getFootprint());
			assertEquals(130, ((DNSKEYRecord) rr).getKey().length);
		}
	}

	@Test
	void DLVKEYRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.DLV);
			assertEquals(Type.DLV, rr.getType());
			assertEquals(60485, ((DLVRecord) rr).getFootprint());
			assertEquals(5, ((DLVRecord) rr).getAlgorithm());
			assertEquals(1, ((DLVRecord) rr).getDigestID());
			assertEquals(20, ((DLVRecord) rr).getDigest().length);
		}
	}

	@Test
	void OpenPGPKEYRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.OPENPGPKEY);
			assertEquals(Type.OPENPGPKEY, rr.getType());
			assertArrayEquals(base64.fromString("CAFEBABE"), ((OPENPGPKEYRecord) rr).getCert());
		}
	}

	@Test
	void CERTRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.CERT);
			assertEquals(Type.CERT, rr.getType());
			assertEquals(CERTRecord.PGP, ((CERTRecord) rr).getCertType());
			assertEquals(0, ((CERTRecord) rr).getAlgorithm());
			assertEquals(0, ((CERTRecord) rr).getKeyTag());
			assertArrayEquals(base64.fromString("CAFEBABE"), ((CERTRecord) rr).getCert());
		}
	}

	@Test
	void SSHFPRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.SSHFP);
			assertEquals(Type.SSHFP, rr.getType());
			assertEquals(SSHFPRecord.Algorithm.DSS, ((SSHFPRecord) rr).getAlgorithm());
			assertEquals(SSHFPRecord.Digest.SHA1, ((SSHFPRecord) rr).getDigestType());
			assertArrayEquals(base16.fromString("CAFEBABE"), ((SSHFPRecord) rr).getFingerPrint());
		}
	}

	@Test
	void PXRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.PX);
			assertEquals(Type.PX, rr.getType());
			assertEquals(10, ((PXRecord) rr).getPreference());
			assertEquals(Name.fromConstantString("net2.it."), ((PXRecord) rr).getMap822());
			assertEquals(Name.fromConstantString("PRMD-net2.ADMD-p400.C-it."), ((PXRecord) rr).getMapX400());
		}
	}

	@Test
	void TLSARecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.TLSA);
			assertEquals(Type.TLSA, rr.getType());
			assertEquals(TLSARecord.CertificateUsage.CA_CONSTRAINT, ((TLSARecord) rr).getCertificateUsage());
			assertEquals(TLSARecord.MatchingType.SHA256, ((TLSARecord) rr).getMatchingType());
			assertEquals(TLSARecord.Selector.FULL_CERTIFICATE, ((TLSARecord) rr).getSelector());
			assertArrayEquals(base16.fromString("CAFEBABE"), ((TLSARecord) rr).getCertificateAssociationData());
		}
	}

	@Test
	void SMIMEARecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.SMIMEA);
			assertEquals(Type.SMIMEA, rr.getType());
			assertEquals(SMIMEARecord.CertificateUsage.DOMAIN_ISSUED_CERTIFICATE, ((SMIMEARecord) rr).getCertificateUsage());
			assertEquals(SMIMEARecord.MatchingType.SHA512, ((SMIMEARecord) rr).getMatchingType());
			assertEquals(SMIMEARecord.Selector.FULL_CERTIFICATE, ((SMIMEARecord) rr).getSelector());
			assertArrayEquals(base16.fromString("CAFEBABE"), ((SMIMEARecord) rr).getCertificateAssociationData());
		}
	}

	@Test
	void NSAPRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.NSAP);
			assertEquals(Type.NSAP, rr.getType());
			assertEquals("G\\000\\005\\128\\000Z\\000\\000\\000\\000\\001\\2253\\255\\255\\255\\000\\001a\\000",
				((NSAPRecord) rr).getAddress());
		}
	}

	@Test
	void NSAP_PTRRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.NSAP_PTR);
			assertEquals(Type.NSAP_PTR, rr.getType());
			assertEquals(Name.fromConstantString("foo.bar.com."),
				((NSAP_PTRRecord) rr).getTarget());
		}
	}

	@Test
	void NXTRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.NXT);
			assertEquals(Type.NXT, rr.getType());
			assertEquals(Name.fromConstantString("medium.foo.tld."),
				((NXTRecord) rr).getNext());
			assertNotNull(((NXTRecord) rr).getBitmap());
		}
	}

	@Test
	void IPSECKEYRecord() throws IOException {
		try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx2"))) {
			Record rr = skipTo(master, Type.IPSECKEY);
			assertEquals(Type.IPSECKEY, rr.getType());
			assertEquals(10, ((IPSECKEYRecord) rr).getPrecedence());
			assertEquals(0, ((IPSECKEYRecord) rr).getGatewayType());
			assertEquals(2, ((IPSECKEYRecord) rr).getAlgorithmType());
			assertNull(((IPSECKEYRecord) rr).getGateway());
			assertArrayEquals(base64.fromString("AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=="),
				((IPSECKEYRecord) rr).getKey());
			rr = master.nextRecord();
			assertEquals(1, ((IPSECKEYRecord) rr).getGatewayType());
			assertTrue(((IPSECKEYRecord) rr).getGateway() instanceof InetAddress);
			rr = master.nextRecord();
			assertEquals(2, ((IPSECKEYRecord) rr).getGatewayType());
			assertTrue(((IPSECKEYRecord) rr).getGateway() instanceof InetAddress);
			rr = master.nextRecord();
			assertEquals(3, ((IPSECKEYRecord) rr).getGatewayType());
			assertEquals(Name.fromConstantString("mygateway.example.com."), ((IPSECKEYRecord) rr).getGateway());
		}
	}

	@Test
	void invalidGenRange() {
		try (Master master = new Master(new ByteArrayInputStream("$GENERATE 3-1".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("Invalid $GENERATE range specifier: 3-1"));
		}
	}

	@Test
	void invalidGenType() {
		try (Master master = new Master(
			new ByteArrayInputStream("$TTL 1h\n$GENERATE 1-3 example.com. MX 10 mail.example.com.".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("$GENERATE does not support MX records"));
		}
	}

	@Test
	void invalidGenerateRangeSpecifier() {
		try (Master master = new Master(new ByteArrayInputStream("$GENERATE 1to20".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("Invalid $GENERATE range specifier"));
		}
	}

	@Test
	void invalidTSIG() {
		try (Master master = new Master(new ByteArrayInputStream("example.com. 0 ANY TSIG".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("no text format defined for TSIG"));
		}
	}

	@Test
	void invalidOPT() {
		try (Master master = new Master(new ByteArrayInputStream("example.com. 0 ANY OPT".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("no text format defined for OPT"));
		}
	}

	@Test
	void invalidTKEY() {
		try (Master master = new Master(new ByteArrayInputStream("example.com. 0 ANY TKEY".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("no text format defined for TKEY"));
		}
	}

	@Test
	void invalidDirective() {
		try (Master master = new Master(new ByteArrayInputStream("$INVALID".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("Invalid directive: $INVALID"));
		}
	}

	@Test
	void missingTTL() {
		try (Master master = new Master(new ByteArrayInputStream("example.com. IN NS ns".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("missing TTL"));
		}
	}

	@Test
	void invalidType() {
		try (Master master = new Master(new ByteArrayInputStream("example.com. IN INVALID".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("Invalid type"));
		}
	}

	@Test
	void noOwner() {
		try (Master master = new Master(new ByteArrayInputStream(" \n ^".getBytes()))) {
			TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
			assertTrue(thrown.getMessage().contains("no owner"));
		}
	}

	@Test
	void invalidOriginNotAbsolute_ctorInputStream() {
		RelativeNameException thrown = assertThrows(RelativeNameException.class, () ->
			new Master((InputStream) null, Name.fromConstantString("notabsolute")));
		assertTrue(thrown.getMessage().contains("'notabsolute' is not an absolute name"));
	}

	@Test
	void invalidOriginNotAbsolute_ctorString() {
		RelativeNameException thrown = assertThrows(RelativeNameException.class, () ->
			new Master("zonefileEx2", Name.fromConstantString("notabsolute")));
		assertTrue(thrown.getMessage().contains("'notabsolute' is not an absolute name"));
	}

	private Record skipTo(Master master, int type) throws IOException {
		Record record;
		do record = master.nextRecord();
		while (record != null && record.getType() != type);
		return record;
	}
}
