import java.io.*;

public class hmacSigner {

private byte [] ipad, opad;
private ByteArrayOutputStream bytes;

static final byte IPAD = 0x36;
static final byte OPAD = 0x5c;
static final byte PADLEN = 64;

static void printByteString(String s, byte [] b, int offset, int length) {
	System.out.print(length + " bytes (" + s + "): ");
	for (int i=offset; i<offset+length; i++) {
		System.out.print("0x");
		System.out.print(Integer.toHexString((int)b[i] & 0xFF) + " ");
		System.out.print(" ");
	}
	System.out.println();
}

public hmacSigner(byte [] key) {
	int i;
	ipad = new byte[PADLEN];
	opad = new byte[PADLEN];
	for (i = 0; i < key.length; i++) {
		ipad[i] = (byte) (key[i] ^ IPAD);
		opad[i] = (byte) (key[i] ^ OPAD);
	}
	for (; i < PADLEN; i++) {
		ipad[i] = IPAD;
		opad[i] = OPAD;
	}
	bytes = new ByteArrayOutputStream();
	try {
		bytes.write(ipad);
	}
	catch (IOException e) {
	}
}

void addData(byte [] b, int offset, int length) {
	if (length < offset || offset >= b.length || length >= b.length)
		return;
/*	printByteString("partial add", b, offset, length);*/
	bytes.write(b, offset, length);
}

void addData(byte [] b) {
/*	printByteString("add", b, 0, b.length);*/
	try {
		bytes.write(b);
	}
	catch (IOException e) {
	}
}

byte [] sign() {
	md5 mdc = new md5(bytes.toByteArray());
	mdc.calc();
	byte [] output = mdc.toBytes();
	bytes = new ByteArrayOutputStream();
	try {
		bytes.write(opad);
		bytes.write(output);
	}
	catch (IOException e) {
	}
	mdc = new md5(bytes.toByteArray());
	mdc.calc();
	byte [] b = mdc.toBytes();
/*	printByteString("sig", b, 0, b.length);*/
	return b;
}

boolean verify(byte [] signature) {
/*	printByteString("ver", signature, 0, signature.length);*/
	return (byteArrayCompare(signature, sign()));
}

static boolean byteArrayCompare(byte [] b1, byte [] b2) {
	if (b1.length != b2.length)
		return false;
	for (int i = 0; i < b1.length; i++)
		if (b1[i] != b2[i])
			return false;
	return true;
}

}
