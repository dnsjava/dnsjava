import java.io.*;
import java.util.*;

public class dnsHeader {

private int id; 
private boolean [] flags;
byte rcode, opcode;
private short [] counts;

static private Random random = new Random();

dnsHeader() {
	counts = new short[4];
	flags = new boolean[16];
}

dnsHeader(CountedDataInputStream in) throws IOException {
	counts = new short[4];
	flags = new boolean[16];
	id = in.readUnsignedShort();
	readFlags(in);
	for (int i=0; i<counts.length; i++)
		counts[i] = in.readShort();
}

void toBytes(DataOutputStream out) throws IOException {
	out.writeShort(id);
	writeFlags(out);
	for (int i=0; i<counts.length; i++)
		out.writeShort(counts[i]);
}

void setFlag(int bit) {
	flags[bit] = true;
}

void unsetFlag(int bit) {
	flags[bit] = false;
}

boolean getFlag(int bit) {
	return flags[bit];
}

int getID() {
	return id;
}

void setID(int id) {
	this.id = id;
}

void setRandomID() {
	id = random.nextInt() & 0xFFFF;
}

void setRcode(byte value) {
	rcode = value;
}

byte getRcode() {
	return rcode;
}

void setOpcode(byte value) {
	opcode = value;
}

byte getOpcode() {
	return opcode;
}

void setCount(int field, short value) {
	counts[field] = value;
}

void incCount(int field) {
	counts[field]++;
}

int getCount(int field) {
	return counts[field];
}

private void writeFlags(DataOutputStream out) throws IOException {
	short flags1 = 0, flags2 = 0;
	for (int i = 0; i < 8; i++) {
		if (flags[i])	flags1 |= (1 << (7-i));
		if (flags[i+8])	flags2 |= (1 << (7-i));
	}
	flags1 |= (opcode << 3);
	flags2 |= (rcode);
	out.writeByte(flags1);
	out.writeByte(flags2);
}

private void readFlags(CountedDataInputStream in) throws IOException {
	short flags1 = (short)in.readUnsignedByte();
	short flags2 = (short)in.readUnsignedByte();
	for (int i = 0; i < 8; i++) {
		flags[i] =	((flags1 & (1 << (7-i))) != 0);
		flags[i+8] =	((flags2 & (1 << (7-i))) != 0);
	}
	opcode = (byte) ((flags1 >> 3) & 0xF);
	rcode = (byte) (flags2 & 0xF);
}

String printFlags() {
	String s;
	StringBuffer sb = new StringBuffer();

	for (int i = 0; i < flags.length; i++)
		if (getFlag(i) && ((s = dns.flagString(i)) != null)) {
			sb.append(s);
			sb.append(" ");
		}
	return sb.toString();
}

}
