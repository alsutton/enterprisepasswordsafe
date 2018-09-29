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

public final class DisablePassword extends HttpServlet {
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
    	ServletUtils servletUtils = ServletUtils.getInstance();
        String id = servletUtils.getParameterValue(request, SharedParameterNames.PASSWORD_ID_PARAMETER);
        User user = SecurityUtils.getRemoteUser(request);

		PasswordStoreManipulator pDAO = UnfilteredPasswordDAO.getInstance();
        try {
	        AccessControl ac = AccessControlDAO.getInstance().getAccessControl(user, id);
	        if(ac == null) {
	        	throw new ServletException("You can not modify the password.");
	        }
	        Password password = pDAO.getById(id, ac);
	        password.setEnabled(false);
	        pDAO.update(password, user, ac);

	        TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
	        		user, password, "Disabled the password", password.getAuditLevel().shouldTriggerEmail());
        } catch(SQLException | GeneralSecurityException e) {
        	throw new ServletException("The password could not be disabled due to an error.", e);
        }

        request.getRequestDispatcher("/system/EditPassword").forward(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Disable a password";
    }

}
