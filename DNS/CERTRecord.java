// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsCERTRecord extends dnsRecord {

short certType, keyTag;
byte alg;
byte [] cert;

static int NOCONF = 0x8000;
static int NOAUTH = 0x4000;

public
dnsCERTRecord(dnsName _name, short _dclass, int _ttl, int _certType,
	      int _keyTag, int _alg, byte []  _cert)
{
	super(_name, dns.CERT, _dclass, _ttl);
	certType = (short) _certType;
	keyTag = (short) _keyTag;
	alg = (byte) _alg;
	cert = _cert;
}

public
dnsCERTRecord(dnsName _name, short _dclass, int _ttl,
	      int length, CountedDataInputStream in, dnsCompression c)
throws IOException
{
	super(_name, dns.CERT, _dclass, _ttl);
	if (in == null)
		return;
	certType = in.readShort();
	keyTag = in.readShort();
	alg = in.readByte();
	if (length > 4) {
		cert = new byte[length - 4];
		in.read(cert);
	}
}

public
dnsCERTRecord(dnsName _name, short _dclass, int _ttl, StringTokenizer st)
throws IOException
{
	super(_name, dns.CERT, _dclass, _ttl);
	certType = (short) Integer.parseInt(st.nextToken());
	keyTag = (short) Integer.parseInt(st.nextToken());
	alg = (byte) Integer.parseInt(st.nextToken());
	cert = base64.fromString(st.nextToken());
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	if (cert != null) {
		sb.append (certType);
		sb.append (" ");
		sb.append (keyTag);
		sb.append (" ");
		sb.append (alg);
		if (cert != null) {
			sb.append (" (\n");
			String s = base64.toString(cert);
			sb.append (dnsIO.formatBase64String(s, 64, "\t", true));
		}
	}
	return sb.toString();
}

public short
getCertType() {
	return certType;
}

public short
getKeyTag() {
	return keyTag;
}

public byte
getAlgorithm() {
	return alg;
}

byte []
rrToWire() throws IOException {
	if (cert == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	DataOutputStream ds = new DataOutputStream(bs);

	ds.writeShort(certType);
	ds.writeByte(keyTag);
	ds.writeByte(alg);
	ds.write(cert);
	return bs.toByteArray();
}

}
