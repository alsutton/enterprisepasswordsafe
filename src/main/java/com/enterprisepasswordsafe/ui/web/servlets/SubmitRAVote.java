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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;


/**
 * Servlet to allow a user to approve or deny a restricted access request.
 */

public final class SubmitRAVote extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = 6172797092993696539L;

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletRequest)
     */
    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
    	throws ServletException, IOException {
        User thisUser = SecurityUtils.getRemoteUser(request);

        try {
	        String id = request.getParameter("rar.id");
	    	RestrictedAccessRequest raRequest = RestrictedAccessRequestDAO.getInstance().getById(id);
	    	if( raRequest == null ) {
	    		throw new ServletException("The request you have tried to vote on does not exist.");
	    	}

	    	final ApproverListDAO alDAO = ApproverListDAO.getInstance();
	        final String currentState = alDAO.getApprovalStateForUser(raRequest, thisUser);
	    	if( currentState == null ) {
	    		throw new ServletException("You are not authorised to approve requests for that password");
	    	}

	        final String includeApprover = ConfigurationDAO.getValue(ConfigurationOption.VOTE_ON_OWN_RA_REQUESTS);
	        if(includeApprover.equals("n")) {
	        	if(raRequest.getRequesterId() == thisUser.getId()) {
	        		throw new ServletException("You are not allowed to vote on your own requests.");
	        	}
	        }

	    	final String vote = request.getParameter("rar_vote");
	    	alDAO.setApprovalStateForUser(raRequest, thisUser, vote);
	    	request.getRequestDispatcher("/system/ra_vote_accepted.jsp").forward(request, response);
        } catch(SQLException sqle) {
        	throw new ServletException("You can not submit your vote at the current time.", sqle);
        }
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Directs the user to the page allowing them to approve or deny a remote access request.";
    }

}
