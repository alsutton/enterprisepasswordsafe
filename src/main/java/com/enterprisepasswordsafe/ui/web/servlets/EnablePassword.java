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

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

/**
 * Servlet to enable a specific password.
 */

public final class EnablePassword extends HttpServlet {
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
	        Password password = UnfilteredPasswordDAO.getInstance().getById(id, ac);
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
        } catch(SQLException | GeneralSecurityException e) {
        	throw new ServletException("The password could not be enabled due to an error.", e);
        }

        response.sendRedirect("/system/EditPassword");
    }

	public String getServletInfo() {
        return "Enable a password";
    }
}
