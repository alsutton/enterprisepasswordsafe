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

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Servlet to create a new password.
 */

public final class DeletePassword extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
    	User remoteUser = SecurityUtils.getRemoteUser(request);
    	try {
    		request.setAttribute("error_page", "/system/ViewPersonalFolder");

    		HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
	        HierarchyNode parentNode = hnDAO.getPersonalNodeForUser(remoteUser);

	    	String passwordId = request.getParameter("id");
	    	String nodeId = hnDAO.getNodeIDForObject(parentNode.getNodeId(), passwordId);
	    	if( nodeId == null ) {
	    		throw new ServletException( "You can not delete that password.");
	    	}

	        AccessControl ac = AccessControlDAO.getInstance().getAccessControl(remoteUser, passwordId);
	        if( ac == null ) {
	        	throw new ServletException("You can not delete the password.");
	        }

	        PasswordDAO pDAO = PasswordDAO.getInstance();
	    	Password thePassword = pDAO.getById(passwordId, ac);
	    	pDAO.delete(remoteUser, thePassword);

	    	ServletUtils.getInstance().generateMessage(request, "The password has been deleted.");
    	} catch(SQLException | GeneralSecurityException e) {
    		throw new ServletException("The password could not be deleted due to an error.", e);
    	}

    	response.sendRedirect(request.getContextPath()+"/system/ViewPersonalFolder");
    }

    @Override
	public String getServletInfo() {
        return "Deletes a password from the users personal folder.";
    }
}
