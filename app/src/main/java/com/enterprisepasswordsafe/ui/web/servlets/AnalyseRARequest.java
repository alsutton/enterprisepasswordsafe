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

import com.enterprisepasswordsafe.database.*;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;


/**
 * Servlet to allow a user to approve or deny a restricted access request.
 */

public final class AnalyseRARequest extends HttpServlet {

    protected String getGenericErrorMessage() {
        return "You can not analyse the request at the current time.";
    }

    protected String getErrorPage() {
        return ServletPaths.getExplorerPath();
    }

    @Override
    protected void doPost( final HttpServletRequest request, final HttpServletResponse response)
    	throws IOException, ServletException {
        User thisUser = SecurityUtils.getRemoteUser(request);

        String id = request.getParameter("rarId");

        RestrictedAccessRequestDAO rarDAO = RestrictedAccessRequestDAO.getInstance();
        try {
	    	RestrictedAccessRequest raRequest = rarDAO.getById(id);
	    	if( raRequest == null ) {
	    		throw new ServletException("The request you have tried to vote on does not exist.");
	    	}

	    	String state = ApproverListDAO.getInstance().getApprovalStateForUser(raRequest, thisUser);
	    	if( state == null ) {
	    		throw new ServletException("You are not authorised to approve or deny the request");
	    	}

	    	User theUser = UserDAO.getInstance().getById(raRequest.getRequesterId());
	    	request.setAttribute("requester", theUser.getUserName());
	    	request.setAttribute("rarId", raRequest.getRequestId());
	    	request.setAttribute("reason", raRequest.getReason());
	    	request.setAttribute("current.state", state);

	    	AccessControledObject aco;

			aco = PasswordDAO.getInstance().getById(thisUser, raRequest.getItemId());
	    	if(aco != null) {
	    		request.setAttribute("aco", aco);
	    	}
		} catch (UnsupportedEncodingException e) {
			// Do nothing, the password could not be accessed
		} catch (GeneralSecurityException | SQLException e) {
			throw new ServletException("You can not analyse the request at the current time.", e);
		}

		request.getRequestDispatcher("/system/ra_vote.jsp").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Directs the user to the page allowing them to approve or deny a remote access request.";
    }

}
