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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
 * Servlet to direct the user to the password defaults editing screen
 */

public final class NodePasswordDefaults extends HttpServlet {

	/**
	 * The access authenticator
	 */

	private static final AccessApprover accessApprover =
		new UserLevelConditionalConfigurationAccessApprover(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);

    /**
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
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

	        Map<String, String> uPerms = new HashMap<String, String>();
	        Map<String, String> gPerms = new HashMap<String, String>();
	        hnDAO.getDefaultPermissionsForNode(nodeId, uPerms, gPerms);

	        Map<String, String> parentUPerms = new HashMap<String, String>();
	        Map<String, String> parentGPerms = new HashMap<String, String>();
	        hnDAO.getCombinedDefaultPermissionsForNode(node.getParentId(), parentUPerms, parentGPerms);

	        String everyonePerm = gPerms.remove(Group.ALL_USERS_GROUP_ID);
	        if( everyonePerm == null ) {
	        	everyonePerm = "0";
	        }
	    	request.setAttribute("egac", everyonePerm);

	    	String everyoneParentPerm = parentGPerms.remove(Group.ALL_USERS_GROUP_ID);
	        if( everyoneParentPerm == null ) {
	        	everyoneParentPerm = "0";
	        }
	    	request.setAttribute("paregac", everyoneParentPerm);

            request.setAttribute("users", UserDAO.getInstance().getAll());
            request.setAttribute("userPermissions", uPerms);
            request.setAttribute("userPermissionsForParent", parentUPerms);
            request.setAttribute("groups", GroupDAO.getInstance().getAll());
            request.setAttribute("groupPermissions", gPerms);
            request.setAttribute("groupPermissionsForParent", parentGPerms);
    	} catch(GeneralSecurityException gse) {
    		throw new ServletException("There was a problem obtaining the password defaults.", gse);
    	} catch(SQLException sqle) {
    		throw new ServletException("There was a problem obtaining the password defaults.", sqle);
    	}
    	request.getRequestDispatcher("/subadmin/edit_subnodes_pdefaults.jsp").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Displays the group permissions for a node.";
    }

    /**
     * Class representing the permissions for an actor.
     */

    public class ActorPermissions
    	implements Comparable<ActorPermissions> {

    	private final String actorId;

    	private final String actorName;

    	private final String parentPermission;

    	private final String permission;

    	/**
    	 * Constructor. Stores information.
    	 */
    	public ActorPermissions(final String newActorId, final String newActorName,
    			final String newParentPermission, final String newPermission) {
    		actorId = newActorId;
    		actorName = newActorName;
    		parentPermission = newParentPermission;
    		permission = newPermission;
    	}

		public String getActorId() {
			return actorId;
		}

		public String getActorName() {
			return actorName;
		}

		public String getParentPermission() {
			return parentPermission;
		}

		public String getPermission() {
			return permission;
		}

		@Override
		public int compareTo(ActorPermissions otherPermission) {
			int returnValue = actorName.compareToIgnoreCase(otherPermission.getActorName());
			if( returnValue == 0 ) {
				returnValue = actorId.compareTo(otherPermission.actorId);
			}
			return returnValue;
		}
    }
}
