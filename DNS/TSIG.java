import java.io.*;
import java.net.*;
import java.util.*;

public class dnsTSIG {

private byte [] key;

dnsTSIG(byte [] key) {
	this.key = key;
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
		h.addData(m.toBytes());

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
	if (tsig == null)
		return false;
/*System.out.println("found TSIG");*/

	hmacSigner h = new hmacSigner(key);
	try {
		if (old != null && tsig.error == dns.NOERROR) {
			h.addData(old.signature);
/*System.out.println("digested query TSIG");*/
		}
		m.getHeader().decCount(dns.ADDITIONAL);
		byte [] header = m.getHeader().toBytes();
		m.getHeader().incCount(dns.ADDITIONAL);
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

}
