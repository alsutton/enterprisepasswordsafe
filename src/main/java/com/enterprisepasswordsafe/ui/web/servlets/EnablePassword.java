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
import java.security.GeneralSecurityException;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.AccessControl;
import com.enterprisepasswordsafe.engine.database.AccessControlDAO;
import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.engine.database.PasswordDAO;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLog;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLogDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Servlet to enable a specific password.
 */

public final class EnablePassword extends HttpServlet {
    /**
	 *
	 */
	private static final long serialVersionUID = 3281728438595209394L;

	/**
     * The generic error message for this servlet.
     */

    private static final String GENERIC_ERROR_MESSAGE = "The password could not be enabled due to an error.";

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#getGenericErrorMessage()
     */

    protected String getGenericErrorMessage() {
        return GENERIC_ERROR_MESSAGE;
    }

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletRequest)
     */
    @Override
    protected void doGet(final HttpServletRequest request, HttpServletResponse response)
    		throws IOException, ServletException {
        String id = ServletUtils.getInstance().getParameterValue(request, SharedParameterNames.PASSWORD_ID_PARAMETER);
        User user = SecurityUtils.getRemoteUser(request);

        try {
	        AccessControl ac = AccessControlDAO.getInstance().getAccessControl(user, id);
	        if( ac == null ) {
	        	throw new ServletException("You can not modify the password.");
	        }
	        Password password = PasswordDAO.getInstance().getByIdEvenIfDisabled(ac, id);
	        password.setEnabled(true);
	        PasswordDAO.getInstance().update(password, user, ac);

	    	boolean sendEmail = ((password.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0);
	        TamperproofEventLogDAO.getInstance().create(
					TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
	        		user,
	        		password,
	        		"Enabled the password",
	        		sendEmail
	    		);
        } catch(SQLException sqle) {
        	throw new ServletException("The password could not be enabled due to an error.", sqle);
        } catch(GeneralSecurityException gse) {
        	throw new ServletException("The password could not be enabled due to an error.", gse);
        }

        response.sendRedirect("/system/EditPassword");
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Enable a password";
    }

}
