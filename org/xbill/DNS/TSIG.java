import java.io.*;
import java.net.*;
import java.util.*;

public class dnsTSIG {

private byte [] key;

dnsTSIG(byte [] key) {
	this.key = key;
}

private static byte [] toCanonicalBytes(dnsMessage m) throws IOException {
        ByteArrayOutputStream os;

        os = new ByteArrayOutputStream();
        m.toCanonicalBytes(new DataOutputStream(os));
        return os.toByteArray();
}

void apply(dnsMessage m) {
	hmacSigner h = new hmacSigner(key);
	try {
		h.addData(toCanonicalBytes(m));
	}
	catch (IOException e) {
		return;
	}
	try {
		String local = InetAddress.getLocalHost().getHostName();
		dnsRecord r;
		r = new dnsTSIGRecord(new dnsName(local), dns.IN, 0,
				      new dnsName(dns.HMAC), new Date(),
				      (short)300, h.sign(), dns.NOERROR, null);
		m.addRecord(dns.ADDITIONAL, r);
	}
	catch (UnknownHostException e) {
	}
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
		h.addData(toCanonicalBytes(m));
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
