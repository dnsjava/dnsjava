// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.utils;

/**
 * A pure java implementation of the MD5 digest algorithm
 *
 * @author Brian Wellington
 */

public final class md5 {

private
md5() {}

private static final int S11 = 7;
private static final int S12 = 12;
private static final int S13 = 17;
private static final int S14 = 22;
private static final int S21 = 5;
private static final int S22 = 9;
private static final int S23 = 14;
private static final int S24 = 20;
private static final int S31 = 4;
private static final int S32 = 11;
private static final int S33 = 16;
private static final int S34 = 23;
private static final int S41 = 6;
private static final int S42 = 10;
private static final int S43 = 15;
private static final int S44 = 21;

private static int
F(int x, int y, int z) {
	return (((x & y)) | (~x & z));
}

private static int
G(int x, int y, int z) {
	return (((x & z)) | (y & ~z));
}

private static int
H(int x, int y, int z) {
	return (x ^ y ^ z);
}

private static int
I(int x, int y, int z) {
	return (y ^ (x | ~z));
}

private static int
ROTATE_LEFT(int x, int n) {
	return ((x << n) | (x >>> (32 - n)));
}

private static int
FF(int a, int b, int c, int d, int x, int s, int ac) {
	a += F(b, c, d) + x + ac;
	a = ROTATE_LEFT(a, s);
	return a + b;
}

private static int
GG(int a, int b, int c, int d, int x, int s, int ac) {
	a += G(b, c, d) + x + ac;
	a = ROTATE_LEFT(a, s);
	return a + b;
}

private static int
HH(int a, int b, int c, int d, int x, int s, int ac) {
	a += H(b, c, d) + x + ac;
	a = ROTATE_LEFT(a, s);
	return a + b;
}

private static int
II(int a, int b, int c, int d, int x, int s, int ac) {
	a += I(b, c, d) + x + ac;
	a = ROTATE_LEFT(a, s);
	return a + b;
}

private static int [] 
decode(byte [] input, int start, int len) {
	int [] output = new int[len/4];
	for (int i = 0, j = start; j < start + len; i++, j+=4)
		output[i] = (input[j] & 0xff) |
			    ((input[j+1] & 0xff) << 8) | 
			    ((input[j+2] & 0xff) << 16) |
			    ((input[j+3] & 0xff) << 24);
	return output;
}

private static byte []
encode(int [] input) {
	byte [] output = new byte[input.length * 4];
	for (int i = 0, j = 0; i < input.length; i++, j+=4) {
		output[j] = (byte)(input[i] & 0xff);
		output[j+1] = (byte)((input[i] >>> 8) & 0xff);
		output[j+2] = (byte)((input[i] >>> 16) & 0xff);
		output[j+3] = (byte)((input[i] >>> 24) & 0xff);
	}
	return output;
}

private static void
digest(byte [] data, int start, int len, int [] s) {
	int [] x = decode(data, start, len);
	int a = s[0], b = s[1], c = s[2], d = s[3];

	a = FF(a, b, c, d, x[0], S11, 0xd76aa478);
	d = FF(d, a, b, c, x[1], S12, 0xe8c7b756);
	c = FF(c, d, a, b, x[2], S13, 0x242070db);
	b = FF(b, c, d, a, x[3], S14, 0xc1bdceee);
	a = FF(a, b, c, d, x[4], S11, 0xf57c0faf);
	d = FF(d, a, b, c, x[5], S12, 0x4787c62a);
	c = FF(c, d, a, b, x[6], S13, 0xa8304613);
	b = FF(b, c, d, a, x[7], S14, 0xfd469501);
	a = FF(a, b, c, d, x[8], S11, 0x698098d8);
	d = FF(d, a, b, c, x[9], S12, 0x8b44f7af);
	c = FF(c, d, a, b, x[10], S13, 0xffff5bb1);
	b = FF(b, c, d, a, x[11], S14, 0x895cd7be);
	a = FF(a, b, c, d, x[12], S11, 0x6b901122);
	d = FF(d, a, b, c, x[13], S12, 0xfd987193);
	c = FF(c, d, a, b, x[14], S13, 0xa679438e);
	b = FF(b, c, d, a, x[15], S14, 0x49b40821);

	a = GG(a, b, c, d, x[1], S21, 0xf61e2562);
	d = GG(d, a, b, c, x[6], S22, 0xc040b340);
	c = GG(c, d, a, b, x[11], S23, 0x265e5a51);
	b = GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
	a = GG(a, b, c, d, x[5], S21, 0xd62f105d);
	d = GG(d, a, b, c, x[10], S22, 0x2441453);
	c = GG(c, d, a, b, x[15], S23, 0xd8a1e681);
	b = GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
	a = GG(a, b, c, d, x[9], S21, 0x21e1cde6);
	d = GG(d, a, b, c, x[14], S22, 0xc33707d6);
	c = GG(c, d, a, b, x[3], S23, 0xf4d50d87);
	b = GG(b, c, d, a, x[8], S24, 0x455a14ed);
	a = GG(a, b, c, d, x[13], S21, 0xa9e3e905);
	d = GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
	c = GG(c, d, a, b, x[7], S23, 0x676f02d9);
	b = GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

	a = HH(a, b, c, d, x[5], S31, 0xfffa3942);
	d = HH(d, a, b, c, x[8], S32, 0x8771f681);
	c = HH(c, d, a, b, x[11], S33, 0x6d9d6122);
	b = HH(b, c, d, a, x[14], S34, 0xfde5380c);
	a = HH(a, b, c, d, x[1], S31, 0xa4beea44);
	d = HH(d, a, b, c, x[4], S32, 0x4bdecfa9);
	c = HH(c, d, a, b, x[7], S33, 0xf6bb4b60);
	b = HH(b, c, d, a, x[10], S34, 0xbebfbc70);
	a = HH(a, b, c, d, x[13], S31, 0x289b7ec6);
	d = HH(d, a, b, c, x[0], S32, 0xeaa127fa);
	c = HH(c, d, a, b, x[3], S33, 0xd4ef3085);
	b = HH(b, c, d, a, x[6], S34, 0x4881d05);
	a = HH(a, b, c, d, x[9], S31, 0xd9d4d039);
	d = HH(d, a, b, c, x[12], S32, 0xe6db99e5);
	c = HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
	b = HH(b, c, d, a, x[2], S34, 0xc4ac5665);

	a = II(a, b, c, d, x[0], S41, 0xf4292244);
	d = II(d, a, b, c, x[7], S42, 0x432aff97);
	c = II(c, d, a, b, x[14], S43, 0xab9423a7);
	b = II(b, c, d, a, x[5], S44, 0xfc93a039);
	a = II(a, b, c, d, x[12], S41, 0x655b59c3);
	d = II(d, a, b, c, x[3], S42, 0x8f0ccc92);
	c = II(c, d, a, b, x[10], S43, 0xffeff47d);
	b = II(b, c, d, a, x[1], S44, 0x85845dd1);
	a = II(a, b, c, d, x[8], S41, 0x6fa87e4f);
	d = II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
	c = II(c, d, a, b, x[6], S43, 0xa3014314);
	b = II(b, c, d, a, x[13], S44, 0x4e0811a1);
	a = II(a, b, c, d, x[4], S41, 0xf7537e82);
	d = II(d, a, b, c, x[11], S42, 0xbd3af235);
	c = II(c, d, a, b, x[2], S43, 0x2ad7d2bb);
	b = II(b, c, d, a, x[9], S44, 0xeb86d391);

	s[0] += a;
	s[1] += b;
	s[2] += c;
	s[3] += d;
}

private static byte []
pad(byte [] data, int start, int len) {
	int size = (len + 8 + 64) & (~63);
	byte [] newdata = new byte[size];
	System.arraycopy(data, start, newdata, 0, len);
	if (size - 8 > len) {
		newdata[len] = (byte) 0x80;
		for (int i = len + 1; i < size - 8; i++)
			newdata[i] = 0;
	}
	int databits = len * 8;
	for (int i = 0; i < 8; i++) {
		newdata[size - 8 + i] = (byte) (databits & 0xff);
		databits >>= 8;
	}
	return newdata;
}

/**
 *  Compute the MD5 digest of a block of data.
 *  @param data The data
 *  @param start The index at which to start digesting
 *  @param len The number of bytes to digest
 *  @return The MD5 digest (a 16 byte array)
 */
public static byte []
compute(byte [] data, int start, int len) {
	int [] s = new int[4];

	s[0] = 0x67452301;
	s[1] = 0xefcdab89;
	s[2] = 0x98badcfe;
	s[3] = 0x10325476;

	byte [] padded = pad(data, start, len);
	for (int i = 0; i < padded.length; i += 64)
		digest(padded, i, 64, s);
	return encode(s);
}

/**
 *  Compute the MD5 digest of a block of data.
 *  @param data The data
 *  @return The MD5 digest (a 16 byte array)
 */
public static byte []
compute(byte [] data) {
	return compute(data, 0, data.length);
}

}
