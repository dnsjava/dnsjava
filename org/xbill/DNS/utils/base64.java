// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS.utils;

import java.io.*;
import java.util.*;

public class base64 {

static private final String Base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

public static String
toString(byte [] b) {
	ByteArrayOutputStream os = new ByteArrayOutputStream();

	for (int i = 0; i < (b.length + 2) / 3; i++) {
		short [] s = new short[3];
		short [] t = new short[4];
		for (int j = 0; j < 3; j++) {
			if ((i * 3 + j) < b.length)
				s[j] = (short) (b[i*3+j] & 0xFF);
			else
				s[j] = -1;
		}
		
		t[0] = (short) (s[0] >> 2);
		if (s[1] == -1)
			t[1] = (short) (((s[0] & 0x3) << 4));
		else
			t[1] = (short) (((s[0] & 0x3) << 4) + (s[1] >> 4));
		if (s[1] == -1)
			t[2] = t[3] = 64;
		else if (s[2] == -1) {
			t[2] = (short) (((s[1] & 0xF) << 2));
			t[3] = 64;
		}
		else {
			t[2] = (short) (((s[1] & 0xF) << 2) + (s[2] >> 6));
			t[3] = (short) (s[2] & 0x3F);
		}
		for (int j = 0; j < 4; j++)
			os.write(Base64.charAt(t[j]));
	}
	return new String(os.toByteArray());
}

public static byte []
fromString(String str) {
	if (str.length() % 4 != 0) {
		return null;
	}
	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	DataOutputStream ds = new DataOutputStream(bs);

	for (int i = 0; i < (str.length() + 3) / 4; i++) {
		short [] s = new short[4];
		short [] t = new short[3];

		for (int j = 0; j < 4; j++)
			s[j] = (short) Base64.indexOf(str.charAt(i*4+j));

		t[0] = (short) ((s[0] << 2) + (s[1] >> 4));
		if (s[2] == 64) {
			t[1] = (short) ((s[1] << 4) & 0xFF);
			t[2] = (short) (-1);
		}
		else if (s[3] == 64) {
			t[1] = (short) (((s[1] << 4) + (s[2] >> 2)) & 0xFF);
			t[2] = (short) ((s[2] << 6) & 0xFF);
		}
		else {
			t[1] = (short) (((s[1] << 4) + (s[2] >> 2)) & 0xFF);
			t[2] = (short) (((s[2] << 6) + s[3]) & 0xFF);
		}

		try {
			for (int j = 0; j < 3; j++)
				if (t[j] >= 0)
					ds.writeByte(t[j]);
		}
		catch (IOException e) {
		}
	}
	return bs.toByteArray();
}

}
