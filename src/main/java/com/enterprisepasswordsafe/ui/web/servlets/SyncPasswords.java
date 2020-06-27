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

import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.database.UserDAO;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;


/**
 * Synchronises the users external and internal passwords.
 */

public final class SyncPasswords extends LoginAuthenticationServlet {

	/**
	 * The parameter name for the internal password
	 */

	public static final String INTERNAL_PASSWORD_PARAMETER = "internalpass";

	/**
	 * The parameter name for the external password.
	 */

	public static final String EXTERNAL_PASSWORD_PARAMETER = "externalpass";

    /**
     * The generic error message for this servlet.
     */

    private static final String GENERIC_ERROR_MESSAGE = "The was a problem attempting to synchronize your passwords.";

    /**
     * The next page to send the user to.
     */

    private static final String NEXT_PAGE_REDIRECT = "./system/Welcome";

    /**
     * The page users are directed to if there is an error.
     */

    private static final String ERROR_PAGE = "/Login";

    protected String getGenericErrorMessage() {
        return GENERIC_ERROR_MESSAGE;
    }

    protected String getErrorPage() {
        return ERROR_PAGE;
    }

    @Override
	protected void doPost( final HttpServletRequest request, final HttpServletResponse response)
    		throws ServletException, IOException {
        String id = request.getParameter(SecurityUtils.USER_ID_PARAMETER);
        String internalpassword = request.getParameter(INTERNAL_PASSWORD_PARAMETER);
        String externalpassword = request.getParameter(EXTERNAL_PASSWORD_PARAMETER);

        // check the username and password were supplied
        if (id == null || internalpassword == null || externalpassword == null) {
        	ServletUtils.getInstance().generateErrorMessage(request, "Unable to synchronize passwords. Please log in again.");
            request.getRequestDispatcher(ERROR_PAGE).forward(request, response);
            return;
        }

        try {
        	UserDAO uDAO = UserDAO.getInstance();
	        User theUser = uDAO.getById(id);
	        try {
	        	uDAO.authenticateUser(theUser, externalpassword);
	        } catch (FailedLoginException fle) {
	        	ServletUtils.getInstance().generateErrorMessage(request, "The details you entered are incorrect");
	            request.getRequestDispatcher(ERROR_PAGE).forward(request, response);
	            return;
	        } catch (LoginException le) {
	        	ServletUtils.getInstance().generateErrorMessage(request, "There was a problem authorising your details", le);
	            request.getRequestDispatcher(ERROR_PAGE).forward(request, response);
	            return;
	        }

	        // If the user has logged in using an external source we need to
	        // ensure the external and EPS password are synchronized.

	        if (!theUser.checkPassword(internalpassword)) {
	        	ServletUtils.getInstance().generateErrorMessage(request, "The details you entered are incorrect");
	            request.getRequestDispatcher(ERROR_PAGE).forward(request, response);
	            return;
	        }

	        // Synchronize the users passwords.
	        theUser.decryptAccessKey(internalpassword);
	        uDAO.updatePassword(theUser, externalpassword);

	        // Store the new details in a session and continue.
	        HttpSession session = request.getSession();
	        storeUserInformation(session, theUser);
	        storeTimeoutInformation(session);

	        response.sendRedirect(NEXT_PAGE_REDIRECT);
        } catch (GeneralSecurityException gse) {
        	ServletUtils.getInstance().generateErrorMessage(request, "There was a problem authorising your details", gse);
            request.getRequestDispatcher(ERROR_PAGE).forward(request, response);
        } catch (SQLException sqle) {
        	ServletUtils.getInstance().generateErrorMessage(request, "There was a problem synchronizing your password", sqle);
            request.getRequestDispatcher(ERROR_PAGE).forward(request, response);
        }
    }

    @Override
	public String getServletInfo() {
        return "Handle synchronizing a users EPS and login source password";
    }
}
