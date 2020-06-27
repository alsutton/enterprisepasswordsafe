/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.utils.IDGenerator;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.StringTokenizer;

/**
 * Representation of an IP address range which rules can be set for.
 */
public class IPZone {
    /**
     * The ID of this IP zone
     */

    private final String zoneId;

    /**
     * The name of this zone
     */

    private String name;

    /**
     * The IP version in use (4 or 6).
     */

    private int ipVersion;

    /**
     * The start IP for the range.
     */
    private String startIp;

    /**
     * The end IP for the range.
     */
    private String endIp;

    /**
     * Constructor. Create a new IP Zone.
     *
     * @param theName The name for this zone.
     * @param firstIp The start IP address in the range.
     * @param lastIp The last IP address in the range.
     */

    public IPZone( String theName, int version, String firstIp, String lastIp ) {
        zoneId = IDGenerator.getID();
        name = theName;
        ipVersion = version;
        startIp = firstIp;
        endIp = lastIp;
    }

    /**
     * Constructor. Extract the data from the ResultSet.
     *
     * @param rs The ResultSet containing the data.
     */

    public IPZone( ResultSet rs )
        throws SQLException {
        int idx = 1;
        zoneId = rs.getString(idx++);
        name = rs.getString(idx++);
        ipVersion = rs.getInt(idx++);
        startIp = rs.getString(idx++);
        endIp = rs.getString(idx);
    }

    /**
     * Get the end IP address of the range.
     *
     * @return Returns the endIp.
     */
    public final String getEndIp() {
        return endIp;
    }

    /**
     * Get the address as a set of sections
     *
     * @return The array of IP address sections for the start IP address.
     */
    public final String getEndIpText() {
    	if			( ipVersion == 4 ) {
    		String[] sections = convertToIPv4Array(endIp);
    		return combineSections(sections, '.');
    	} else if	( ipVersion == 6 ) {
    		return convertToIPv6Address(endIp);
    	}
    	return null;
    }

    /**
     * Set the last IP in the range.
     *
     * @param newEndIp The endIp to set.
     */
    public final void setEndIp(String newEndIp) {
        endIp = newEndIp;
    }

    /**
     * Get the name of this IP Zone.
     *
     * @return Returns the name.
     */
    public final String getName() {
        return name;
    }

    /**
     * Set the name for this range.
     *
     * @param newName The name to set.
     */
    public final void setName(String newName) {
        name = newName;
    }

    /**
     * Get the start IP for this range.
     *
     * @return Returns the startIp.
     */
    public final String getStartIp() {
        return startIp;
    }

    /**
     * Get the address as a set of sections
     *
     * @return The array of IP address sections for the start IP address.
     */
    public final String getStartIpText() {
    	if			( ipVersion == 4 ) {
    		String[] sections = convertToIPv4Array(startIp);
    		return combineSections(sections, '.');
    	} else if	( ipVersion == 6 ) {
    		return convertToIPv6Address(startIp);
    	}
    	return null;
    }

    /**
     * Set the start address for the range.
     *
     * @param newStartIp The startIp to set.
     */
    public final void setStartIp(String newStartIp) {
        startIp = newStartIp;
    }

    /**
     * Get the ID for this zone.
     *
     * @return Returns the zoneId.
     */
    public final String getId() {
        return zoneId;
    }

    /**
     * Get the IP version for this range.
     *
     * @return The IP version for the range
     */

    public int getIpVersion() {
    	return ipVersion;
    }

    /**
     * Sets the IP version for this range.
     *
     * @param newIpVersion The IP Version.
     */

    public void setIpVersion(int newIpVersion) {
    	ipVersion = newIpVersion;
    }

    /**
     * Convert an IP address string into an array of numbers.
     *
     * @param original The original string representation of the numbers.
     */

    private String[] convertToIPv4Array(String original) {
    	String[] value = new String[4];
    	for(int i = 0, j = 0 ; i < 12; i+=3, j++) {
    		value[j] = original.substring(i, i+3);
    		while( value[j].charAt(0) == '0' && value[j].length() > 1) {
    			value[j] = value[j].substring(1);
    		}
    	}
    	return value;
    }

    /**
     * Convert an IP address string into an array of hex numbers as used
     * in IPv6.
     *
     * @param original The original string representation of the numbers.
     */

    private String convertToIPv6Address(String original) {
        if(original.length() < 48) {
            return "Bad Address";

        }

    	StringBuilder result = new StringBuilder(48);
        for(int i = 0, j = 0 ; i < 48 ; i+=6, j++) {
            String	sectionOne = original.substring(i, i+3),
                    sectionTwo = original.substring(i+3, i+6);

            int sectionValue = (Integer.parseInt(sectionOne) << 8) +
                                Integer.parseInt(sectionTwo);
            result.append(Integer.toHexString(sectionValue));
            result.append(':');
        }
        result.deleteCharAt(result.length()-1);
        return result.toString();
    }

    /**
     * Combines all the sections of an string using the given seperator.
     *
     * @param sections The sections to combine.
     * @param separator The separator to use.
     *
     * @return The combined string.
     */

    public String combineSections( String[] sections, char separator ) {
    	StringBuilder result = new StringBuilder();
        for(String section : sections) {
    		result.append(section);
    		result.append(separator);
    	}
    	result.deleteCharAt(result.length()-1);
    	return result.toString();
    }

    /**
     * Convert an IPv6 format IP address to a database string.
     *
     * @param original The original IPv6 representation.
     *
     * @return A textual representation.
     */

    public static String convertIP6ToDBString(String original)
    	throws UnknownHostException, GeneralSecurityException {
    	StringBuilder dbString = new StringBuilder(48);

    	InetAddress ipAddress = InetAddress.getByName(original);
    	String fullRepresentation = ipAddress.getHostAddress();

    	StringTokenizer strTok = new StringTokenizer(fullRepresentation, ":");
    	if( strTok.countTokens() != 8 ) {
    		throw new GeneralSecurityException
    			("Your JVM does not represent IPv6 Addresses correctly ("+fullRepresentation+")");
    	}
    	try {
	    	while(strTok.hasMoreTokens()) {
	    		int elementValue = Integer.parseInt(strTok.nextToken(), 16);
	    		addToBuffer(dbString, (elementValue&0xff00)>>8);
	    		addToBuffer(dbString, (elementValue&0x00ff)   );
	    	}
	    	return dbString.toString();
    	} catch(NumberFormatException nfe) {
    		return null;
    	}
    }

    /**
     * Convert an IPv4 format IP address to a database string.
     *
     * @param original The original IPv4 representation.
     *
     * @return A textual representation.
     */

    public static String convertIP4ToDBString(String original)
    	throws GeneralSecurityException {
    	StringBuilder dbString = new StringBuilder(12);

    	StringTokenizer strTok = new StringTokenizer(original, ".");
    	if( strTok.countTokens() != 4 ) {
    		throw new GeneralSecurityException
    			("Your JVM does not represent IPv4 Addresses correctly ("+original+")");
    	}
    	while(strTok.hasMoreTokens()) {
    		int elementValue = Integer.parseInt(strTok.nextToken());
    		addToBuffer(dbString, elementValue);
    	}

    	return dbString.toString();
    }

    /**
     * Add a value into a StringBuffer as a three character decimal.
     *
     * @param buffer The buffer to add the value to.
     * @param value The value to add.
     */

    public static void addToBuffer(StringBuilder buffer, int value) {
		if( value <  10 ) {
			buffer.append("00");
		} else if( value <  100 ) {
			buffer.append('0');
		}
		buffer.append(value);
    }
}
