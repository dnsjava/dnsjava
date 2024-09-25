package org.xbill.DNS;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
enum SetResponseType {
    /** The Cache contains no information about the requested name/type */
    UNKNOWN(false, true),

    /**
     * The Zone does not contain the requested name, or the Cache has determined that the name does
     * not exist.
     */
    NXDOMAIN(false, true),

    /**
     * The Zone contains the name, but no data of the requested type, or the Cache has determined that
     * the name exists and has no data of the requested type.
     */
    NXRRSET(false, true),

    /** A delegation enclosing the requested name was found. */
    DELEGATION(true, false),

    /**
     * The Cache/Zone found a CNAME when looking for the name.
     *
     * @see CNAMERecord
     */
    CNAME(true, false),

    /**
     * The Cache/Zone found a DNAME when looking for the name.
     *
     * @see DNAMERecord
     */
    DNAME(true, false),

    /** The Cache/Zone has successfully answered the question for the requested name/type/class. */
    SUCCESSFUL(false, false);

    private final boolean printRecords;

    /** If true, no RRsets can be added. Intended for static NX* instances. */
    private final boolean isSealed;
}