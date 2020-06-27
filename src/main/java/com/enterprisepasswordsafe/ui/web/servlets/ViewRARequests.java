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

import com.enterprisepasswordsafe.database.ApproverListDAO;
import com.enterprisepasswordsafe.database.RestrictedAccessRequest;
import com.enterprisepasswordsafe.database.RestrictedAccessRequestDAO;
import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;
import java.util.TreeSet;

/**
 * Servlet to alter the event email settings.
 */

public final class ViewRARequests extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = -1579953695564789934L;

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletRequest)
     */
	@Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    		throws ServletException {
    	try {
	        User thisUser = SecurityUtils.getRemoteUser(request);

	        Set<RASummary> summaries = new TreeSet<>();

	        ApproverListDAO alDAO = ApproverListDAO.getInstance();
	        for(RestrictedAccessRequest rar : RestrictedAccessRequestDAO.getInstance().getRARsForUser(thisUser)) {
	        	String state = alDAO.getApprovalStateForUser(rar, thisUser);
	        	rar.getApproversListId();
	        	summaries.add(new RASummary(rar, state));
	        }

	        request.setAttribute("requests_for_approval", summaries);
	        request.getRequestDispatcher("/system/ra_outstanding.jsp").forward(request, response);
    	} catch (Exception ex) {
    		throw new ServletException("The system is unable to check your restricted access requests at this time", ex);
    	}
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Servlet to store the users Email settings in the database";
    }

    /**
     * Class holding the summary of a restricted access request.
     */

    public static class RASummary
    	implements Comparable<RASummary> {

    	/**
    	 * The ID of the summary.
    	 */

    	private final String id;

    	/**
    	 * The ID of the object involved in the RA request.
    	 */

    	private final String objectId;

    	/**
    	 * The current state.
    	 */

    	private final String state;

    	/**
    	 * Constructor. Stores relevant data.
    	 *
    	 * @param ra The restricted access request this is a summary for.
    	 * @param newState The current state of the RAr
    	 */
    	public RASummary( RestrictedAccessRequest ra, String newState ) {
    		id = ra.getRequestId();
    		objectId = ra.getItemId();
    		state = newState;
    	}

		public String getId() {
			return id;
		}

		public String getObjectId() {
			return objectId;
		}

		public String getState() {
			return state;
		}

		@Override
		public int compareTo(RASummary otherObject) {
			return id.compareTo(otherObject.id);
		}

		@Override
		public boolean equals(Object otherObject) {
			if(!(otherObject instanceof RASummary)) {
				return false;
			}
			return id.equals(((RASummary)otherObject).id);
		}

		@Override
		public int hashCode() {
			return id.hashCode();
		}
    }
}
