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

import java.sql.SQLException;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.AccessRole.ApproverSummary;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.ui.web.utils.ApprovalRequestMailer;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

public final class ViewRAPassword extends HttpServlet {

	public static final String REASON_PARAMETER = "reason";

	private final UserClassifier userClassifier = new UserClassifier();

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
    		throws ServletException {
    	try {
	        User thisUser = SecurityUtils.getRemoteUser(request);

	        String passwordId = ServletUtils.getInstance().getParameterValue(request, "id");
	        AccessControl ac;
	        if (userClassifier.isPriviledgedUser(thisUser)) {
	            ac = AccessControlDAO.getInstance().getAccessControlEvenIfDisabled(thisUser, passwordId);
	        } else {
	            ac = AccessControlDAO.getInstance().getAccessControl(thisUser, passwordId);
	        }
	        Password password = PasswordDAO.getInstance().getById(passwordId, ac);

	        if (ac == null) {
	        	ServletUtils.getInstance().generateMessage(request,"You are not allowed to view the selected password.");
	        	request.getRequestDispatcher(ServletPaths.getExplorerPath()).forward(request, response);
	        	return;
	        }
	        password.decrypt(ac);

	        String includeApprover =
					ConfigurationDAO.getInstance().get(ConfigurationOption.VOTE_ON_OWN_RA_REQUESTS);
	        String ignoreUserId = null;
	        if(includeApprover.equals("n")) {
		        ignoreUserId = thisUser.getId();
	        }

	        String reason = request.getParameter(REASON_PARAMETER);
	        RestrictedAccessRequest raRequest =
	        	RestrictedAccessRequestDAO.getInstance().create(
	        			passwordId,
	        			thisUser.getId(),
	        			reason,
	        			ignoreUserId
	    			);

			String approvalURL =
					getServerBaseURL(request) + "/system/AnalyseRARequest?rarId=" + raRequest.getRequestId();

	        Set<ApproverSummary> approvers = AccessRoleDAO.getInstance().getApprovers(passwordId, ignoreUserId);

	    	new ApprovalRequestMailer(approvers, thisUser, password, raRequest, approvalURL).start();

	    	request.setAttribute("otid", request.getSession().getAttribute("nextOtid"));
	    	request.getRequestDispatcher("/system/ViewPassword").forward(request, response);
    	} catch(Exception ex) {
    		throw new ServletException("You can not view the request at the current time because of an error.", ex);
    	}
    }

	private String getServerBaseURL(final HttpServletRequest request)
		throws SQLException {
		String baseUrl = ConfigurationDAO.getValue(ConfigurationOption.PROPERTY_SERVER_BASE_URL);
		if(baseUrl == null || baseUrl.isEmpty()) {
			baseUrl = constructBaseURLFromRequest(request);
		}
		return baseUrl;
	}

	private String constructBaseURLFromRequest(final HttpServletRequest request) {
		StringBuilder baseUrl = new StringBuilder();
		baseUrl.append(request.getScheme());
		baseUrl.append("://");
		baseUrl.append(request.getServerName());
		int serverPort = request.getServerPort();
		if( serverPort != 80 ) {
			baseUrl.append(':');
			baseUrl.append(request.getServerPort());
		}
		baseUrl.append(request.getContextPath());
		return baseUrl.toString();
	}
}
