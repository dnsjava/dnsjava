// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class CERTRecord extends Record {

short certType, keyTag;
byte alg;
byte [] cert;

static int NOCONF = 0x8000;
static int NOAUTH = 0x4000;

public
CERTRecord(Name _name, short _dclass, int _ttl, int _certType,
	      int _keyTag, int _alg, byte []  _cert)
{
	super(_name, Type.CERT, _dclass, _ttl);
	certType = (short) _certType;
	keyTag = (short) _keyTag;
	alg = (byte) _alg;
	cert = _cert;
}

public
CERTRecord(Name _name, short _dclass, int _ttl,
	      int length, DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.CERT, _dclass, _ttl);
	if (in == null)
		return;
	certType = in.readShort();
	keyTag = in.readShort();
	alg = in.readByte();
	if (length > 5) {
		cert = new byte[length - 5];
		in.read(cert);
	}
}

public
CERTRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	   Name origin)
throws IOException
{
	super(_name, Type.CERT, _dclass, _ttl);
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
			sb.append (IO.formatBase64String(s, 64, "\t", true));
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

void
rrToWire(DataByteOutputStream dbs, Compression c) throws IOException {
	if (cert == null)
		return;

	dbs.writeShort(certType);
	dbs.writeByte(keyTag);
	dbs.writeByte(alg);
	dbs.write(cert);
}

}
