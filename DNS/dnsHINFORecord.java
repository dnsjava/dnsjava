// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.util.*;
import java.io.*;

public class dnsHINFORecord extends dnsRecord {

String cpu, OS;

public dnsHINFORecord(dnsName rname, short rclass) {
	super(rname, dns.HINFO, rclass);
}

public dnsHINFORecord(dnsName rname, short rclass, int ttl, String cpu,
		      String OS) {
	this(rname, rclass);
	this.rttl = rttl;
	this.rlength = (short) (cpu.length() + OS.length() + 2);
	this.cpu = cpu;
	this.OS = OS;
}

void parse(CountedDataInputStream in, dnsCompression c) throws IOException {
	int len = in.readByte();
	byte [] b = new byte[len];
	in.read(b);
	cpu = new String(b);

	len = in.readByte();
	b = new byte[len];
	in.read(b);
	cpu = new String(b);
}

void rrToBytes(DataOutputStream out) throws IOException {
	out.writeByte(cpu.getBytes().length);
	out.write(cpu.getBytes());
	out.writeByte(OS.getBytes().length);
	out.write(OS.getBytes());
}

void rrToCanonicalBytes(DataOutputStream out) throws IOException {
	rrToBytes(out);
}

String rrToString() {
	if (rlength == 0)
		return null;
	StringBuffer sb = new StringBuffer();
	sb.append("\"");
	sb.append(cpu);
	sb.append("\" \"");
	sb.append(OS);
	sb.append("\"");
	return sb.toString();
}

}
