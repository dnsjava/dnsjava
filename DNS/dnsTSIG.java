import java.io.*;
import java.net.*;
import java.util.*;

public class dnsTSIG {

private byte [] key;

dnsTSIG(byte [] key) {
	this.key = key;
}

private static byte [] toBytes(dnsMessage m) throws IOException {
	ByteArrayOutputStream os;

	os = new ByteArrayOutputStream();
	m.toBytes(new DataOutputStream(os));
	return os.toByteArray();
}

void apply(dnsMessage m) {
	hmacSigner h = new hmacSigner(key);

	Date timeSigned = new Date();
	short fudge = 300;
	String local;
	try {
		local = InetAddress.getLocalHost().getHostName();
	}
	catch (UnknownHostException e) {
		return;
	}
	dnsName name = new dnsName(local);
	dnsName alg = new dnsName(dns.HMAC);

	try {
		h.addData(toBytes(m));
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream dout = new DataOutputStream(out);
		alg.toCanonicalBytes(dout);
		long time = timeSigned.getTime() / 1000;
		short timeHigh = (short) (time >> 32);
		int timeLow = (int) (time);
		dout.writeShort(timeHigh);
		dout.writeInt(timeLow);
		dout.writeShort(fudge);

		dout.writeShort(0); /* No error */
		dout.writeShort(0); /* No other data */

		h.addData(out.toByteArray());
	}
	catch (IOException e) {
		return;
	}
	dnsRecord r = new dnsTSIGRecord(name, dns.IN, 0, alg, timeSigned, fudge,
					h.sign(), dns.NOERROR, null);
	m.addRecord(dns.ADDITIONAL, r);
}

/*
 * Since this is only called in the context where a TSIG is expected, it
 * is an error to not have one.
 */
boolean verify(dnsMessage m) {
	int count = m.getHeader().getCount(dns.ADDITIONAL);
	if (count == 0)
		return false;
	Vector v = m.getSection(dns.ADDITIONAL);
	dnsRecord rec = (dnsRecord) v.elementAt(count - 1);
	if (!(rec instanceof dnsTSIGRecord))
		return false;
	dnsTSIGRecord tsig = (dnsTSIGRecord) rec;
	m.removeRecord(dns.ADDITIONAL, tsig);

	hmacSigner h = new hmacSigner(key);
	try {
		h.addData(toBytes(m));
	}
	catch (IOException e) {
		return false;
	}

	if (h.verify(tsig.signature))
		return true;
	else
		return false;
}

}
