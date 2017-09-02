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

import java.io.IOException;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.PasswordRestriction;
import com.enterprisepasswordsafe.engine.database.PasswordRestrictionDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

/**
 * Adds a password restriction to the system
 */

public final class PasswordRestrictionsEditStage2 extends HttpServlet {

	/**
	 *
	 */
	private static final long serialVersionUID = 7902867050803032684L;

	/**
	 * The parameter holding the id of this restriction.
	 */

	public static final String ID_PARAMETER = "id";

	/**
	 * The parameter holding the name of this restriction.
	 */

	public static final String NAME_PARAMETER = "name";

    /**
     * The parameter holding the lifetime for the password.
     */

    public static final String LIFETIME_PARAMETER = "lifetime";

    /**
     * The generic error message for this servlet.
     */

    private static final String GENERIC_ERROR_MESSAGE = "The restriction could not be added.";

    /**
     * The page users are directed to if there is an error.
     */

    private static final String ERROR_PAGE = "/admin/PasswordRestrictionsEditStage1";

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletResponse)
     */
    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	String id = request.getParameter(ID_PARAMETER);
    	PasswordRestrictionDAO prDAO = PasswordRestrictionDAO.getInstance();

    	PasswordRestriction restriction;
    	try {
    		restriction = prDAO.getById(id);
    	} catch(SQLException ex) {
    		request.setAttribute("error_page", ERROR_PAGE);
    		throw new ServletException(GENERIC_ERROR_MESSAGE, ex);
    	}

    	try {
    		restriction.setMinSpecial(Integer.parseInt(request.getParameter(PasswordRestrictionsAddStage2.SPECIAL_COUNT_PARAMETER)));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum number of special characters must be an integer value.");
    	}

    	try {
    		restriction.setMinNumeric(Integer.parseInt(request.getParameter(PasswordRestrictionsAddStage2.NUMERIC_COUNT_PARAMETER)));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum number of numeric characters must be an integer value.");
    	}

    	try {
    		restriction.setMinUpper(Integer.parseInt(request.getParameter(PasswordRestrictionsAddStage2.UPPER_COUNT_PARAMETER)));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum number of upper case characters must be an integer value.");
    	}

    	try {
    		restriction.setMinLower(Integer.parseInt(request.getParameter(PasswordRestrictionsAddStage2.LOWER_COUNT_PARAMETER)));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum number of lower case characters must be an integer value.");
    	}

    	try {
    		restriction.setMinLength(Integer.parseInt(request.getParameter(PasswordRestrictionsAddStage2.MIN_SIZE_PARAMETER)));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The minimum length must be an integer value.");
    	}

    	try {
    		restriction.setMaxLength(Integer.parseInt(request.getParameter("size_max")));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The maximum length must be an integer value.");
    	}

    	try {
    		restriction.setLifetime(Integer.parseInt(request.getParameter(LIFETIME_PARAMETER)));
    	} catch(NumberFormatException nfe) {
    		throw new ServletException( "The default validity must be an integer value.");
    	}

    	restriction.setSpecialCharacters(request.getParameter(PasswordRestrictionsAddStage2.SPECIAL_CHARACTERS_PARAMETER));
    	restriction.setName(request.getParameter(NAME_PARAMETER));

    	try {
    		prDAO.update(restriction);
    	} catch(SQLException ex) {
    		request.setAttribute("error_page", ERROR_PAGE);
    		throw new ServletException(GENERIC_ERROR_MESSAGE, ex);
    	}

        ServletUtils.getInstance().generateMessage(request, restriction.getName()+" has been updated.");
        response.sendRedirect(request.getContextPath()+"/admin/PasswordRestrictions");
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Adds a password restriction to the system.";
    }
}
