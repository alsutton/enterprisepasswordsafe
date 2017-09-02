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
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.ui.web.servlets.authorisation.AccessApprover;
import com.enterprisepasswordsafe.ui.web.servlets.authorisation.UserLevelConditionalConfigurationAccessApprover;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Servlet to direct the user to the hierarchy editing screen.
 */

public final class NodeUserPermissions extends HttpServlet {
	/**
	 *
	 */
	private static final long serialVersionUID = -3829184507016986232L;
	/**
	 * The access authenticator
	 */

	private static final AccessApprover accessApprover =
		new UserLevelConditionalConfigurationAccessApprover(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletRequest)
     */
    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    		throws ServletException, IOException {
    	try {
	    	User remoteUser = SecurityUtils.getRemoteUser(request);
	    	SecurityUtils.isAllowedAccess(accessApprover, remoteUser);

	        String nodeId = ServletUtils.getInstance().getNodeId(request);

	        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
	        HierarchyNode node = hnDAO.getById(nodeId);
	        List<HierarchyNode> parentage = hnDAO.getParentage(node);

	        request.setAttribute(BaseServlet.NODE, node);
	        request.setAttribute(BaseServlet.NODE_PARENTAGE, parentage);

	        if(!node.getNodeId().equals(HierarchyNode.ROOT_NODE_ID)) {
	            Group adminGroup = GroupDAO.getInstance().getAdminGroup(remoteUser);
	            request.setAttribute("users", UserDAO.getInstance().getSummaryListExcludingAdmin());
	            request.setAttribute("perms", HierarchyNodeAccessRuleDAO.getInstance().getAccessibilityRules(node, adminGroup));
	        }
    	} catch(GeneralSecurityException gse) {
    		throw new ServletException("There was a problem obtaining the user permissions.", gse);
    	} catch(SQLException sqle) {
    		throw new ServletException("There was a problem obtaining the user permissions.", sqle);
    	}

    	request.getRequestDispatcher("/subadmin/edit_subnodes_upermissions.jsp").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Displays the user permissions for a node.";
    }
}
