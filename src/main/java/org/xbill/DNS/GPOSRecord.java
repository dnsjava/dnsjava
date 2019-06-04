// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;

/**
 * Geographical Location - describes the physical location of a host.
 * (withdrawn -- this was a limited early version of {@link LOCRecord})
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1712">RFC 1712: DNS Encoding of Geographical Location</a>
 */
public class GPOSRecord extends Record {

private static final long serialVersionUID = -6349714958085750705L;

private byte [] latitude, longitude, altitude;

GPOSRecord() {}

@Override
Record
getObject() {
	return new GPOSRecord();
}

private void
validate(double longitude, double latitude) throws IllegalArgumentException
{
       if (longitude < -90.0 || longitude > 90.0) {
               throw new IllegalArgumentException("illegal longitude " +
                                                  longitude);
       }
       if (latitude < -180.0 || latitude > 180.0) {
               throw new IllegalArgumentException("illegal latitude " +
                                                  latitude);
       }
}

/**
 * Creates an GPOS Record from the given data
 * @param longitude The longitude component of the location.
 * @param latitude The latitude component of the location.
 * @param altitude The altitude component of the location (in meters above sea
 * level).
*/
public
GPOSRecord(Name name, int dclass, long ttl, double longitude, double latitude,
	   double altitude)
{
	super(name, Type.GPOS, dclass, ttl);
	validate(longitude, latitude);
	this.longitude = Double.toString(longitude).getBytes();
	this.latitude = Double.toString(latitude).getBytes();
	this.altitude = Double.toString(altitude).getBytes();
}

/**
 * Creates an GPOS Record from the given data
 * @param longitude The longitude component of the location.
 * @param latitude The latitude component of the location.
 * @param altitude The altitude component of the location (in meters above sea
 * level).
*/
public
GPOSRecord(Name name, int dclass, long ttl, String longitude, String latitude,
	   String altitude)
{
	super(name, Type.GPOS, dclass, ttl);
	try {
		this.longitude = byteArrayFromString(longitude);
		this.latitude = byteArrayFromString(latitude);
		validate(getLongitude(), getLatitude());
		this.altitude = byteArrayFromString(altitude);
	}
	catch (TextParseException e) {
		throw new IllegalArgumentException(e.getMessage());
	}
}

@Override
void
rrFromWire(DNSInput in) throws IOException {
	longitude = in.readCountedString();
	latitude = in.readCountedString();
	altitude = in.readCountedString();
	try {
		validate(getLongitude(), getLatitude());
	}
	catch(IllegalArgumentException e) {
		throw new WireParseException(e.getMessage());
	}
}

@Override
void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	try {
		longitude = byteArrayFromString(st.getString());
		latitude = byteArrayFromString(st.getString());
		altitude = byteArrayFromString(st.getString());
	}
	catch (TextParseException e) {
		throw st.exception(e.getMessage());
	}
	try {
		validate(getLongitude(), getLatitude());
	}
	catch(IllegalArgumentException e) {
		throw new WireParseException(e.getMessage());
	}
}

/** Convert to a String */
@Override
String
rrToString() {
	StringBuilder sb = new StringBuilder();
	sb.append(byteArrayToString(longitude, true));
	sb.append(" ");
	sb.append(byteArrayToString(latitude, true));
	sb.append(" ");
	sb.append(byteArrayToString(altitude, true));
	return sb.toString();
}

/** Returns the longitude as a string */
public String
getLongitudeString() {
	return byteArrayToString(longitude, false);
}

/**
 * Returns the longitude as a double
 * @throws NumberFormatException The string does not contain a valid numeric
 * value.
 */
public double
getLongitude() {
	return Double.parseDouble(getLongitudeString());
}

/** Returns the latitude as a string */
public String
getLatitudeString() {
	return byteArrayToString(latitude, false);
}

/**
 * Returns the latitude as a double
 * @throws NumberFormatException The string does not contain a valid numeric
 * value.
 */
public double
getLatitude() {
	return Double.parseDouble(getLatitudeString());
}

/** Returns the altitude as a string */
public String
getAltitudeString() {
	return byteArrayToString(altitude, false);
}

/**
 * Returns the altitude as a double
 * @throws NumberFormatException The string does not contain a valid numeric
 * value.
 */
public double
getAltitude() {
	return Double.parseDouble(getAltitudeString());
}

@Override
void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	out.writeCountedString(longitude);
	out.writeCountedString(latitude);
	out.writeCountedString(altitude);
}

}
