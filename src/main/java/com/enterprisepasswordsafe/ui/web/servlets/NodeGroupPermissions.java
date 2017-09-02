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

public final class NodeGroupPermissions extends HttpServlet {
	/**
	 *
	 */
	private static final long serialVersionUID = -9126307844781159465L;

	/**
	 * The access authenticator
	 */

	private static final AccessApprover accessApprover =
		new UserLevelConditionalConfigurationAccessApprover(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);

	/**
	 * The parameter for storing the access list
	 */

	public static final String PERMISSION_LIST_PARAMETER = "perms";

	/**
	 * The parameter for the group list.
	 */

	public static final String GROUP_LIST = "groups";

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletRequest)
     */
    @Override
	protected void doGet(final HttpServletRequest request,
    		final HttpServletResponse response)
    	throws ServletException, IOException {
    	try {
	    	User remoteUser = SecurityUtils.getRemoteUser(request);
	    	SecurityUtils.isAllowedAccess(accessApprover, remoteUser);

	    	ServletUtils su = ServletUtils.getInstance();
	        String nodeId = su.getNodeId(request);

	        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
	        HierarchyNode node = hnDAO.getById(nodeId);
	        List<HierarchyNode> parentage = hnDAO.getParentage(node);

	        request.setAttribute(BaseServlet.NODE, node);
	        request.setAttribute(BaseServlet.NODE_PARENTAGE, parentage);

	        su.setCurrentNodeId(request, nodeId);
	        if(!node.getNodeId().equals(HierarchyNode.ROOT_NODE_ID)) {
	            request.setAttribute(GROUP_LIST, GroupDAO.getInstance().getAll());
	            request.setAttribute(PERMISSION_LIST_PARAMETER,
	            		HierarchyNodeAccessRuleDAO.getInstance().getGroupAccessibilityRules(node));
	        }
    	} catch(GeneralSecurityException gse) {
    		throw new ServletException("There was a problem obtaining the group permissions.", gse);
    	} catch(SQLException sqle) {
    		throw new ServletException("There was a problem obtaining the group permissions.", sqle);
    	}
    	request.getRequestDispatcher("/subadmin/edit_subnodes_gpermissions.jsp").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Displays the group permissions for a node.";
    }
}
