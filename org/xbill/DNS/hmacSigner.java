import java.io.*;

public class hmacSigner {

private byte [] ipad, opad;
private ByteArrayOutputStream bytes;

static final byte IPAD = 0x36;
static final byte OPAD = 0x5c;
static final byte PADLEN = 64;

public void hmacSigner(byte [] key) {
	int i;
	ipad = new byte[PADLEN];
	opad = new byte[PADLEN];
	for (i = 0; i < key.length; i++) {
		ipad[i] = (byte) (key[i] & IPAD);
		opad[i] = (byte) (key[i] & OPAD);
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

void addData(byte [] b) {
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
	return mdc.toBytes();
}

}
