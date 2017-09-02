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
 * Servlet to create a folder in the hierarchy.
 */

public final class CreateNode extends HttpServlet {
	/**
	 * The access authenticator
	 */

	private static final AccessApprover accessApprover =
		new UserLevelConditionalConfigurationAccessApprover(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);

    /**
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
        ServletUtils servletUtils = ServletUtils.getInstance();

    	User user = SecurityUtils.getRemoteUser(request);
    	try {
	    	SecurityUtils.isAllowedAccess(accessApprover, user);

	        String parentId = servletUtils.getNodeId(request);
	        String name = request.getParameter("name");

	        HierarchyNode newNode = HierarchyNodeDAO.getInstance().create(name, parentId, HierarchyNode.CONTAINER_NODE);
	    	HierarchyNodeAccessRuleDAO.getInstance().setAccessibleByUser(newNode, user, HierarchyNodeAccessRuleDAO.ACCESIBILITY_ALLOWED	);
	        TamperproofEventLogDAO.getInstance().create(
	        				TamperproofEventLog.LOG_LEVEL_HIERARCHY_MANIPULATION,
	        				user,
	        				null,
	        				"Added {node:" + newNode.getNodeId() +
	        					"} into the hierarchy under {node:" + parentId + "}",
	        				true
						);

	        servletUtils.generateMessage(request, "The node has been created.");
    	} catch(Exception ex) {
            servletUtils.generateErrorMessage(request, "The node could not be added due to an error.", ex);
    	}
        request.getRequestDispatcher("/subadmin/EditHierarchy").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Creates a new node within the hierarchy";
    }
}
