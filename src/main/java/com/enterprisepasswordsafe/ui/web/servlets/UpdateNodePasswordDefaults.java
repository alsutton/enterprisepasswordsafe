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
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.actions.ChangePermissionsAction;
import com.enterprisepasswordsafe.engine.hierarchy.HierarchyTools;
import com.enterprisepasswordsafe.ui.web.servlets.authorisation.AccessApprover;
import com.enterprisepasswordsafe.ui.web.servlets.authorisation.UserLevelConditionalConfigurationAccessApprover;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

public final class UpdateNodePasswordDefaults extends HttpServlet {

	private static final AccessApprover accessApprover =
		new UserLevelConditionalConfigurationAccessApprover(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);

	private final HierarchyTools hierarchyTools = new HierarchyTools();

    @Override
	protected void doPost( final HttpServletRequest request, final HttpServletResponse response)
    	throws ServletException, IOException {
    	try {
	    	User remoteUser = SecurityUtils.getRemoteUser(request);
	    	SecurityUtils.isAllowedAccess(accessApprover, remoteUser);

	        String nodeId = ServletUtils.getInstance().getNodeId(request);
	        Map<String, String> uPerms = new HashMap<>();
	        Map<String, String> gPerms = new HashMap<>();

			Enumeration<String> paramNames = request.getParameterNames();
	        while( paramNames.hasMoreElements() ) {
	        	String name = paramNames.nextElement();
	        	if( name.startsWith("gperm_") ) {
	        		String value = request.getParameter(name);
	        		if( value != null && value.length() > 0 && !value.equals("0")) {
	        			gPerms.put(name.substring(6), value);
	        		}
	        	} else if( name.startsWith("uperm_") ) {
	        		String value = request.getParameter(name);
	        		if( value != null && value.length() > 0 && !value.equals("0")) {
	        			uPerms.put(name.substring(6), value);
	        		}
	        	}
	        }

	    	HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
	        String recursivelyApply = request.getParameter("cascade");
	        if( recursivelyApply != null && recursivelyApply.length() > 0 ) {
	        	HierarchyNode node = hnDAO.getById(nodeId);
	        	Group adminGroup = GroupDAO.getInstance().getAdminGroup(remoteUser);
	        	ChangePermissionsAction action = new ChangePermissionsAction(adminGroup, node, uPerms, gPerms);
	        	applyPermissions(remoteUser, hnDAO, node, uPerms, gPerms, action);
	        } else {
	        	new HierarchyNodePermissionDAO().setDefaultPermissionsForNode(nodeId, uPerms, gPerms);
	        }

	        ServletUtils.getInstance().generateMessage(request, "The default permissions have been updated");
    	} catch(Exception sqle) {
    		throw new ServletException("There was a problem obtaining the password defaults.", sqle);
    	}

        response.sendRedirect(request.getContextPath()+"/subadmin/NodePasswordDefaults");
    }

    private void applyPermissions(final User remoteUser, final HierarchyNodeDAO hnDAO, final HierarchyNode node,
    		final Map<String, String> uPerms, final Map<String, String> gPerms, final ChangePermissionsAction action)
    	throws Exception {
    	new HierarchyNodePermissionDAO().setDefaultPermissionsForNode(node.getNodeId(), uPerms, gPerms);
    	hierarchyTools.processObjectNodes(node, remoteUser, action, false);
    	for(HierarchyNode thisNode : hnDAO.getChildrenContainerNodesForUser(node, remoteUser, true, null)) {
    		applyPermissions(remoteUser, hnDAO, thisNode, uPerms, gPerms, action);
    	}
    }
}
