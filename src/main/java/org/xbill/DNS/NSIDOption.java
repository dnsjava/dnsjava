// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * The Name Server Identifier Option
 *
 * @see OPTRecord
 * 
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc5001">RFC 5001: DNS Name Server Identifier (NSID) Option</a>
 */
public class NSIDOption extends GenericEDNSOption {

private static final long serialVersionUID = 74739759292589056L;

NSIDOption() {
	super(EDNSOption.Code.NSID);
}

/**
 * Construct an NSID option.
 * @param data The contents of the option.
 */
public 
NSIDOption(byte [] data) {
	super(EDNSOption.Code.NSID, data);
}

}
