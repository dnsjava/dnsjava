import java.io.*;

public class base64 {

static final byte[] Base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".getBytes();

public static String toString(byte [] b) {
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
			os.write(Base64[t[j]]);
	}
	return new String(os.toByteArray());
}

}
