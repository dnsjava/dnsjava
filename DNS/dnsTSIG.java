import java.io.*;
import java.net.*;
import java.util.*;

public class dnsTSIG {

private byte [] key;
private hmacSigner axfrSigner;

dnsTSIG(byte [] key) {
	this.key = key;
}

void apply(dnsMessage m) {
	Date timeSigned = new Date();
	short fudge = 300;
	String local;
	hmacSigner h = new hmacSigner(key);

	try {
		local = InetAddress.getLocalHost().getHostName();
	}
	catch (UnknownHostException e) {
		return;
	}
	dnsName name = new dnsName(local);
	dnsName alg = new dnsName(dns.HMAC);

	try {
		/* Digest the message after zeroing out the id */
		int id = m.getHeader().getID();
		m.getHeader().setID(0);
		h.addData(m.toBytes());
		m.getHeader().setID(id);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream dout = new DataOutputStream(out);
		name.toCanonicalBytes(dout);
		dout.writeShort(dns.ANY);	/* class */
		dout.writeInt(0);		/* ttl */
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
	dnsRecord r = new dnsTSIGRecord(name, dns.ANY, 0, alg, timeSigned,
					fudge, h.sign(), dns.NOERROR, null);
	m.addRecord(dns.ADDITIONAL, r);
}

/*
 * Since this is only called in the context where a TSIG is expected, it
 * is an error to not have one.  Note that we need to take an unparsed message
 * as input, since we can't recreate the wire format exactly (with the same
 * name compression).
 */
boolean verify(dnsMessage m, byte [] b, dnsTSIGRecord old) {
	dnsTSIGRecord tsig = m.getTSIG();
	hmacSigner h = new hmacSigner(key);
	if (tsig == null)
		return false;
/*System.out.println("found TSIG");*/

	try {
		if (old != null && tsig.error == dns.NOERROR) {
			h.addData(old.signature);
/*System.out.println("digested query TSIG");*/
		}
		m.getHeader().decCount(dns.ADDITIONAL);
		int id = m.getHeader().getID();
		m.getHeader().setID(0);
		byte [] header = m.getHeader().toBytes();
		m.getHeader().incCount(dns.ADDITIONAL);
		m.getHeader().setID(id);
		h.addData(header);

		int len = b.length - header.length;	
		len -= tsig.toBytes(dns.ADDITIONAL).length;
		h.addData(b, header.length, len);
/*System.out.println("digested message");*/

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream dout = new DataOutputStream(out);
		tsig.rname.toCanonicalBytes(dout);
		dout.writeShort(tsig.rclass);
		dout.writeInt(tsig.rttl);
		tsig.alg.toCanonicalBytes(dout);
		long time = tsig.timeSigned.getTime() / 1000;
		short timeHigh = (short) (time >> 32);
		int timeLow = (int) (time);
		dout.writeShort(timeHigh);
		dout.writeInt(timeLow);
		dout.writeShort(tsig.fudge);
		dout.writeShort(tsig.error);
		if (tsig.other != null) {
			dout.writeShort(tsig.other.length);
			dout.write(tsig.other);
		}
		else
			dout.writeShort(0);

		h.addData(out.toByteArray());
/*System.out.println("digested variables");*/
	}
	catch (IOException e) {
		return false;
	}

	if (h.verify(tsig.signature))
		return true;
	else
		return false;
}

void verifyAXFRStart() {
	axfrSigner = new hmacSigner(key);
}

boolean verifyAXFR(dnsMessage m, byte [] b, boolean required) {
	dnsTSIGRecord tsig = m.getTSIG();
	hmacSigner h = axfrSigner;
	
	try {
		if (tsig != null)
			m.getHeader().decCount(dns.ADDITIONAL);
		int id = m.getHeader().getID();
		m.getHeader().setID(0);
		byte [] header = m.getHeader().toBytes();
		if (tsig != null)
			m.getHeader().incCount(dns.ADDITIONAL);
		m.getHeader().setID(id);
		h.addData(header);

		int len = b.length - header.length;	
		if (tsig != null)
			len -= tsig.rrLength();
		h.addData(b, header.length, len);

		if (tsig == null) {
			if (required)
				return false;
			else
				return true;
		}

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream dout = new DataOutputStream(out);
		long time = tsig.timeSigned.getTime() / 1000;
		short timeHigh = (short) (time >> 32);
		int timeLow = (int) (time);
		dout.writeShort(timeHigh);
		dout.writeInt(timeLow);
		dout.writeShort(tsig.fudge);
		h.addData(out.toByteArray());
	}
	catch (IOException e) {
		return false;
	}

	if (h.verify(tsig.signature) == false) {
		return false;
	}

	h.clear();
	h.addData(tsig.signature);

	return true;
}

}
