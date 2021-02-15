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

package com.enterprisepasswordsafe.model.utils;

import com.enterprisepasswordsafe.model.persisted.IPZone;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.StringTokenizer;

/**
 * Representation of an IP address range which rules can be set for.
 */
public class IPZoneUtils {

    /**
     * Get the address as a set of sections
     *
     * @return The array of IP address sections for the start IP address.
     */
    public static String getEndIpText(IPZone zone) {
		return convertToString(zone.getIpVersion(), zone.getIpEnd());
    }

    /**
     * Covert the Start IP Address in a zone to a single String.
     *
	 * @Param zone The zone to convert.
     * @return The address as a String.
     */
    public static String getStartIpText(IPZone zone) {
    	return convertToString(zone.getIpVersion(), zone.getIpStart());
    }

    private static String convertToString(int ipVersion, String ipAddress) {
    	switch(ipVersion) {
			case 4:
				String[] sections = convertToIPv4Array(ipAddress);
				return String.join(".", sections);
			case 6:
				return convertToIPv6Address(ipAddress);
			default:
				return null;
		}
	}

    /**
     * Convert an IP address string into an array of numbers.
     *
     * @param original The original string representation of the numbers.
     */

    private static String[] convertToIPv4Array(String original) {
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

    private static String convertToIPv6Address(String original) {
        if(original.length() < 48) {
            return "Bad Address";

        }

    	StringBuilder result = new StringBuilder(48);
        for(int i = 0; i < 48 ; i+=6) {
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
