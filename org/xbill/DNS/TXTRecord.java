// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;

/**
 * Text - stores text strings
 *
 * @author Brian Wellington
 */

public class TXTRecord extends TXTBase {

TXTRecord() {}

Record
getObject() {
	return new TXTRecord();
}

/**
 * Creates a TXT Record from the given data
 * @param strings The text strings
 * @throws IllegalArgumentException One of the strings has invalid escapes
 */
public
TXTRecord(Name name, int dclass, long ttl, List strings) {
	super(name, Type.TXT, dclass, ttl, strings);
}

/**
 * Creates a TXT Record from the given data
 * @param string One text string
 * @throws IllegalArgumentException The string has invalid escapes
 */
public
TXTRecord(Name name, int dclass, long ttl, String string) {
	super(name, Type.TXT, dclass, ttl, string);
}

}
