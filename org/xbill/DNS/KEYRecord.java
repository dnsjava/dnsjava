// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class KEYRecord extends Record {

short flags;
byte proto, alg;
byte [] key;

/* flags */
public static final int NOCONF = 0x8000;
public static final int NOAUTH = 0x4000;

public
KEYRecord(Name _name, short _dclass, int _ttl, int _flags, int _proto,
	  int _alg, byte []  _key)
{
	super(_name, Type.KEY, _dclass, _ttl);
	flags = (short) _flags;
	proto = (byte) _proto;
	alg = (byte) _alg;
	key = _key;
}

public
KEYRecord(Name _name, short _dclass, int _ttl,
	     int length, CountedDataInputStream in, Compression c)
throws IOException
{
	super(_name, Type.KEY, _dclass, _ttl);
	if (in == null)
		return;
	flags = in.readShort();
	proto = in.readByte();
	alg = in.readByte();
	if (length > 4) {
		key = new byte[length - 4];
		in.read(key);
	}
}

public
KEYRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	  Name origin)
throws IOException
{
	super(_name, Type.KEY, _dclass, _ttl);
	flags = (short) Integer.decode(st.nextToken()).intValue();
	proto = (byte) Integer.parseInt(st.nextToken());
	alg = (byte) Integer.parseInt(st.nextToken());
	key = base64.fromString(st.nextToken());
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	if (key != null || (flags & (NOAUTH|NOCONF)) == (NOAUTH|NOCONF) ) {
		sb.append ("0x");
		sb.append (Integer.toHexString(flags));
		sb.append (" ");
		sb.append (proto);
		sb.append (" ");
		sb.append (alg);
		if (key != null) {
			sb.append (" (\n");
			String s = base64.toString(key);
			sb.append (IO.formatBase64String(s, 64, "\t", true));
		}
	}
	return sb.toString();
}

public short
getFlags() {
	return flags;
}

public byte
getProtocol() {
	return proto;
}

public byte
getAlgorithm() {
	return alg;
}

public byte []
getKey() {
	return key;
}

byte []
rrToWire(Compression c, int index) throws IOException {
	if (key == null && (flags & (NOAUTH|NOCONF)) != (NOAUTH|NOCONF) )
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	CountedDataOutputStream ds = new CountedDataOutputStream(bs);

	ds.writeShort(flags);
	ds.writeByte(proto);
	ds.writeByte(alg);
	if (key != null)
		ds.write(key);
	return bs.toByteArray();
}

}
