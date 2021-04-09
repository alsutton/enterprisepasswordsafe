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

package com.enterprisepasswordsafe.ui.web.servlets;

import com.enterprisepasswordsafe.model.utils.IPZoneUtils;
import com.enterprisepasswordsafe.model.dao.IPZoneDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.StringTokenizer;


/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class StoreIPZone extends HttpServlet {
    /**
     * The numeric representation of ::
     */

    private static final String IPV6_ALL_ZEROS = "000000000000000000000000000000000000000000000000";


    /**
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	try {
	        String zoneName = request.getParameter("zonename");
	        if( zoneName == null || zoneName.length() == 0 ) {
	            throw new ServletException( "A name must be specified.");
	        }

	        String ipVersionString = request.getParameter("ip.version");
	        int ipVersion = Integer.parseInt(ipVersionString);

	        String startIp, endIp;
	        if( ipVersion == 4 ) {
	        	startIp = getIPv4String( request, "start" );
	        	endIp = getIPv4String( request, "end" );
	        } else if ( ipVersion == 6 ) {
	        	startIp = getIPv6String( request, "start");
	        	endIp = getIPv6String( request, "end" );
	        } else {
	        	throw new ServletException("IP Version type unknown ("+ipVersion+")");
	        }

	        IPZoneDAO ipzDAO = IPZoneDAO.getInstance();
	        String id = request.getParameter("zoneid");
	        if( id != null && id.length() > 0 ) {
	        	IPZoneUtils thisZone = ipzDAO.getById(id);
	            thisZone.setName(zoneName);
	            thisZone.setIpVersion(ipVersion);
	            thisZone.setStartIp(startIp);
	            thisZone.setEndIp(endIp);
	            ipzDAO.update(thisZone);
	        } else {
	        	ipzDAO.create(zoneName, ipVersion, startIp, endIp);
	        }

	        ServletUtils.getInstance().generateMessage(request, "The zone has been updated.");
	        response.sendRedirect(request.getContextPath()+"/admin/EditIPZones");
        } catch(ParseException pe) {
            throw new ServletException("The zone count not be created", pe);
    	} catch(SQLException sqle) {
    		throw new ServletException("The IP zone could not be created.", sqle);
    	}
    }

    /**
     * Construct the textual representation of the IP address.
     *
     *  @param request The HttpServletRequest being served.
     *  @param field The field holding the IPv4 representation.
     *
     *  @return The string representation.
     */

    private String getIPv4String(HttpServletRequest request, String field)
        throws ParseException {
        String representation = request.getParameter(field);
        StringTokenizer stringTokenizer = new StringTokenizer(representation, ".");
        if(stringTokenizer.countTokens() != 4) {
            throw new ParseException("Incorrect number of values for an IPv4 address", 0);
        }

        StringBuilder result = new StringBuilder(12);
        while(stringTokenizer.hasMoreTokens()) {
            int value = Integer.parseInt(stringTokenizer.nextToken());
            IPZoneUtils.addToBuffer(result, value);
        }
    	return result.toString();
    }

    /**
     * Construct the textual representation and IPv6 Address
     *
     * @param request The HttpServletRequest being served.
     * @param field The field name holding the user entered value.
     *
     * @return The string representation.
     */

    private String getIPv6String(HttpServletRequest request, String field) {
        String value = request.getParameter(field);

        if(!value.contains("::")) {
            return mergeSections(value);
        } else if (value.equals("::")) {
            return IPV6_ALL_ZEROS;
        }

        int colonCount = 0;
        for(char c : value.toCharArray()) {
            if(c == ':') {
                colonCount++;
            }
        }

        if  (value.startsWith("::")) {
            value = value.replace("::", createZeroFields(9-colonCount));
        } else if (value.endsWith("::")) {
            value = value.replace("::", ":"+createZeroFields(9-colonCount));
        } else {
            value = value.replace("::", ":"+createZeroFields(8-colonCount));
        }

        return mergeSections(value);
    }

    /**
     * Create a representation of a number of zeros to fill a specified number of places in an IPv6 address
     *
     * @param count The number of spaces to create zeros for.
     *
     * @return The appropriate number of zeros as a string
     */

    private String createZeroFields(int count) {
        StringBuilder result = new StringBuilder(count*6);
        result.append("0:".repeat(Math.max(0, count)));
        return result.toString();
    }

    /**
     * Merge the sections of an IPv6 Address
     *
     * @param value The full IPv6 address
     *
     * @return The merged value
     */

    private String mergeSections(final String value) {
        StringBuilder result = new StringBuilder();
        StringTokenizer stringTokenizer = new StringTokenizer(value, ":");
        while(stringTokenizer.hasMoreTokens()) {
            addExpandedIPv6Value(result, stringTokenizer.nextToken());
        }
        return result.toString();
    }

    /**
     * Convert a String representing part of a IPv6 address to a decimal representation
     *
     * @param builder The StringBuilder to add the value to.
     * @param value The value to convert.
     */

    private void addExpandedIPv6Value(final StringBuilder builder, final String value) {
        int section = Integer.parseInt(value, 16);
        IPZoneUtils.addToBuffer(builder, (section&0xff00)>>8);
        IPZoneUtils.addToBuffer(builder, (section&0x00ff)   );
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Servlet to store information about a network zone.";
    }
}
