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
import com.enterprisepasswordsafe.ui.web.servlets.authorisation.AccessApprover;
import com.enterprisepasswordsafe.ui.web.servlets.authorisation.UserLevelConditionalConfigurationAccessApprover;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;


/**
 * Servlet to alter the personal details of a user (Full name and email).
 */
public final class UpdateHierarchyPermissions extends HttpServlet {
	/**
	 * The access authenticator
	 */

	private static final AccessApprover accessApprover =
		new UserLevelConditionalConfigurationAccessApprover(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);

    /**
     * The extension for parameters which hold the new permission settings.
     */

    public static final String NEW_PERMISSIONS_EXTENSION = "_perms";

    /**
     * The extension for parameters which hold the original permission settings.
     */

    public static final String ORIGINAL_PERMISSIONS_EXTENSION = "_orig";

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	try {
	    	final User remoteUser = SecurityUtils.getRemoteUser(request);

	    	SecurityUtils.isAllowedAccess(accessApprover, remoteUser);
	        final Group adminGroup = GroupDAO.getInstance().getAdminGroup(remoteUser);

	    	final String nodeId = ServletUtils.getInstance().getNodeId(request);
	        final HierarchyNode theNode = HierarchyNodeDAO.getInstance().getById(nodeId);

	        for(Object paramNameObject : request.getParameterMap().keySet()) {
	            final String paramName = paramNameObject.toString();
	            if(paramName.endsWith(NEW_PERMISSIONS_EXTENSION)) {
	                updatePermissions(request, adminGroup, theNode, paramName);
	            }
	        }

	        ServletUtils.getInstance().generateMessage(request, "Permissions updated.");
    	} catch(Exception ex) {
    		throw new ServletException("There was a problem updating the permissions.", ex);
    	}

    	response.sendRedirect(request.getContextPath()+"/subadmin/NodeUserPermissions");
    }


    /**
     * Update the permissions for a specific user.
     *
     * @param request The request being serviced.
     * @param adminGroup The admin group used to decrypt the users key.
	 * @param node The node being altered.
     * @param paramName The name of the parameter holding the new permissions.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem encrypting the rule.
	 */

    private void updatePermissions(final HttpServletRequest request, final Group adminGroup,
            final HierarchyNode node, final String paramName )
            throws SQLException, GeneralSecurityException {

        String newRule = request.getParameter(paramName);

        String userId = paramName.substring(
                                0,
                                paramName.length() - NEW_PERMISSIONS_EXTENSION.length()
                            );

        String originalPermissionParamName = userId + ORIGINAL_PERMISSIONS_EXTENSION;
        String originalRule = request.getParameter(originalPermissionParamName);

        if (originalRule.equals(newRule)) {
            return;
        }

        byte rule = Byte.parseByte(newRule);

        User user = UserDAO.getInstance().getByIdDecrypted(userId, adminGroup);
        if( user == null ) {
        	return;
        }
        HierarchyNodeAccessRuleDAO.getInstance().setAccessibleByUser(node, user, rule);
    }

    @Override
	public String getServletInfo() {
        return "Servlet to update the permissions on a hierarchy node.";
    }

}
