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

import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;


/**
 * Adds a password restriction to the system
 */

public final class PasswordRestrictionsAddStage2 extends HttpServlet {

	/**
	 * The parameter holding the name of this restriction.
	 */

	public static final String NAME_PARAMETER = "name";

    /**
     * The parameter holding the minimum number of special characters.
     */

    public static final String SPECIAL_COUNT_PARAMETER = "special_min";

    /**
     * The parameter holding the minimum number of numeric characters.
     */

    public static final String NUMERIC_COUNT_PARAMETER = "numeric_min";

    /**
     * The parameter holding the minimum number of upper case characters.
     */

    public static final String UPPER_COUNT_PARAMETER = "upper_min";

    /**
     * The parameter holding the minimum number of lower case characters.
     */

    public static final String LOWER_COUNT_PARAMETER = "lower_min";

    /**
     * The parameter for the minimum length for a password
     */
	public static final String MIN_SIZE_PARAMETER = "size_min";

    /**
     * The parameter for the maximum length for a password
     */
	public static final String MAX_SIZE_PARAMETER = "size_max";

	/**
     * The parameter holding the special characters
     */

    public static final String SPECIAL_CHARACTERS_PARAMETER = "chars_special";

    /**
     * The parameter holding the lifetime for the password.
     */

    public static final String LIFETIME_PARAMETER = "lifetime";

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	request.setAttribute("error_page", "/admin/PasswordRestrictionsAddStage1");
    	int specialCount;
    	try {
    		specialCount =	Integer.parseInt(request.getParameter(SPECIAL_COUNT_PARAMETER));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum number of special characters must be an integer value.");
    	}

    	int numericCount;
    	try {
    		numericCount =	Integer.parseInt(request.getParameter(NUMERIC_COUNT_PARAMETER));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum number of numeric characters must be an integer value.");
    	}

    	int upperCount;
    	try {
    		upperCount = 	Integer.parseInt(request.getParameter(UPPER_COUNT_PARAMETER));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum number of upper case characters must be an integer value.");
    	}

    	int lowerCount;
    	try {
    		lowerCount = 	Integer.parseInt(request.getParameter(LOWER_COUNT_PARAMETER));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum number of lower case characters must be an integer value.");
    	}

    	int minLength;
    	try {
    		minLength = Integer.parseInt(request.getParameter(MIN_SIZE_PARAMETER));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum length must be an integer value.");
    	}

    	int maxLength;
    	try {
    		maxLength = Integer.parseInt(request.getParameter(MAX_SIZE_PARAMETER));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum length must be an integer value.");
    	}

    	int lifespan;
    	try {
    		lifespan = 	Integer.parseInt(request.getParameter(LIFETIME_PARAMETER));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The default validity must be an integer value.");
    	}

    	String specialCharacters = request.getParameter(SPECIAL_CHARACTERS_PARAMETER);
    	String name = request.getParameter(NAME_PARAMETER);

    	try {
	    	PasswordRestrictionDAO.getInstance().create(
	 			name, lowerCount, upperCount, numericCount,	specialCount,
	 			minLength, maxLength, specialCharacters, lifespan );
    	} catch(SQLException sqle) {
    		throw new ServletException("The restriction could not be added.", sqle);
    	}

        ServletUtils.getInstance().generateMessage(request, name+" has been created.");

        response.sendRedirect(request.getContextPath()+"/admin/PasswordRestrictions");
    }

    @Override
	public String getServletInfo() {
        return "Adds a password restriction to the system.";
    }
}
