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
import com.enterprisepasswordsafe.database.derived.HierarchyNodeChildren;
import com.enterprisepasswordsafe.engine.hierarchy.HierarchyTools;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Comparator;


/**
 * Handles the user interacting with the password hierarchy.
 */

public final class Explorer extends HttpServlet {

    private static final String INCLUDE_EMPTY_ATTRIBUTE = "_include_empty";

	private UserClassifier userClassifier = new UserClassifier();
	private HierarchyTools hierarchyTools = new HierarchyTools();

    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	request.setAttribute("isInExplorer", Boolean.TRUE);

        User user = SecurityUtils.getRemoteUser(request);

        ServletUtils su = ServletUtils.getInstance();
        String nodeId = su.getNodeId(request);
        if(nodeId == null) {
        	nodeId = HierarchyNode.ROOT_NODE_ID;
        }

        try {
	        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
	        HierarchyNode node = getClosestValidNodeToRequested(request, user, nodeId);
	    	su.setCurrentNodeId(request, node.getNodeId());

	    	request.setAttribute(INCLUDE_EMPTY_ATTRIBUTE,
              ConfigurationDAO.getValue(ConfigurationOption.HIDE_EMPTY_FOLDERS).equals(Configuration.HIDE_EMPTY_FOLDERS_OFF));

	        determineHierarchyEditability(request, user);

	        request.setAttribute(BaseServlet.NODE, node);
	        request.setAttribute(BaseServlet.NODE_PARENTAGE, hierarchyTools.getParentage(node));
	        request.setAttribute(BaseServlet.NODE_CHILDREN, getVisibleChildren(request, user, node));
        } catch( GeneralSecurityException | SQLException e ) {
        	throw new ServletException("The password explorer encountered an error.", e);
        }
        request.getRequestDispatcher("/system/view_subnodes.jsp").forward(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Obtains and displays the information about a node in the hierarchy";
    }

    private HierarchyNode getClosestValidNodeToRequested(HttpServletRequest request, User user, String nodeId)
			throws SQLException, GeneralSecurityException {
		HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
		HierarchyNode node = hnDAO.getById(nodeId);
		if(node == null || node.getType() == HierarchyNode.USER_CONTAINER_NODE) {
			nodeId = HierarchyNode.ROOT_NODE_ID;
			node = hnDAO.getById(nodeId);
		}

        HierarchyNodeAccessRuleDAO hnarDAO = HierarchyNodeAccessRuleDAO.getInstance();
		if (userClassifier.isAdministrator(user)) {
		    return node;
        }

        ServletUtils.getInstance().generateErrorMessage(request, "You are not allowed access to the folder "+
                "you requested. You have been diverted to a folder you can access.");
        for(HierarchyNode thisNode : hierarchyTools.getParentage(node)) {
            if(hnarDAO.getAccessibilityForUser(thisNode, user) != HierarchyNodeAccessRuleDAO.ACCESIBILITY_DENIED) {
                return thisNode;
            }
        }
		return hnDAO.getById(HierarchyNode.ROOT_NODE_ID);
	}

    private void determineHierarchyEditability(HttpServletRequest request, User user)
			throws SQLException {
		request.setAttribute("edithierarchy_allowed", "N");
		if(userClassifier.isNonViewingUser(user)) {
		    return;
        }

        if			( userClassifier.isAdministrator(user) ) {
            request.setAttribute("edithierarchy_allowed", "Y");
            return;
        }

        if	( userClassifier.isSubadministrator(user) ){
            String displayEdit = ConfigurationDAO.getValue(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);
            if( displayEdit != null && 	displayEdit.equals("S") ) {
                request.setAttribute("edithierarchy_allowed", "Y");
                request.setAttribute(INCLUDE_EMPTY_ATTRIBUTE, Boolean.TRUE);
            }
        }
	}

	private HierarchyNodeChildren getVisibleChildren(HttpServletRequest request, User user, HierarchyNode node)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        String sortOrder = getSortOrder(request);
        Comparator<Password> objectComparator;
        if (sortOrder != null && sortOrder.startsWith("S")) {
            objectComparator = new SystemComparator();
        } else {
            objectComparator = new UsernameComparator();
        }

        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
        HierarchyNodeChildren children =
                hierarchyTools.getChildrenValidForUser(node, user,
                        ((Boolean)request.getAttribute(INCLUDE_EMPTY_ATTRIBUTE)), null, objectComparator);
        if(userClassifier.isNonViewingUser(user)) {
            children.setObjects(null);
        }
        return children;
    }

    private String getSortOrder(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        String sortOrder = request.getParameter(BaseServlet.SORT_PARAMETER);
        if (sortOrder == null) {
            sortOrder = (String) session.getAttribute(BaseServlet.SORT_PARAMETER);
        }
        session.setAttribute(BaseServlet.SORT_PARAMETER, sortOrder);
        return sortOrder;
    }


    private abstract class PasswordComparator implements Comparator<Password>, Serializable {

        protected abstract String getKeyString(Object passwordObject) throws Exception;

        protected abstract String getSecondaryString(Object passwordObject) throws Exception;

        @Override
		public int compare(final Password passwordObject0, final Password passwordObject1) {
        	try {
	            if (passwordObject0 == passwordObject1) {
	                return 0;
	            }
	            if (passwordObject0 == null) {
	                return Integer.MIN_VALUE;
	            }
	            if (passwordObject1 == null) {
	                return Integer.MAX_VALUE;
	            }

	            if(passwordObject0.getId().equals(passwordObject1.getId())) {
	            	return 0;
	            }

				int keyComparison = compareKeys(passwordObject0, passwordObject1);
	            return keyComparison == 0 ? passwordObject0.getId().compareTo(passwordObject1.getId()) : keyComparison;
        	} catch( Exception ex ) {
        		throw new RuntimeException(ex);
        	}
        }

        private int compareKeys(final Password passwordObject0, final Password passwordObject1)
				throws Exception {
			int primaryKeyComparison = compareIndividualKeys(getKeyString(passwordObject0), getKeyString(passwordObject1));
			return primaryKeyComparison == 0 ?
					compareIndividualKeys(getSecondaryString(passwordObject0), getSecondaryString(passwordObject1))
				:	primaryKeyComparison;
		}

		private int compareIndividualKeys(String key0, String key1) {
			if (key0 == null) {
				return Integer.MIN_VALUE;
			}
			if (key1 == null) {
				return Integer.MAX_VALUE;
			}

			int caseInsensitiveComparison = key0.compareToIgnoreCase(key1);
			if (caseInsensitiveComparison != 0) {
				return caseInsensitiveComparison;
			}

			int caseSensitiveComparison = key0.compareTo(key1);
			if( caseSensitiveComparison != 0 ) {
				return caseSensitiveComparison;
			}

			return  0;
		}
    }

    private class UsernameComparator extends PasswordComparator {

        @Override
		protected String getKeyString(final Object passwordObject) {
            if (passwordObject instanceof PasswordBase) {
                return ((PasswordBase) passwordObject).getUsername();
            }
            return null;
        }

        @Override
		protected String getSecondaryString(final Object passwordObject) {
            if (passwordObject instanceof PasswordBase) {
                return ((PasswordBase) passwordObject).getLocation();
            }

            return null;
        }
    }

    private class SystemComparator extends PasswordComparator {

        @Override
		protected String getKeyString(final Object passwordObject) {
            if (passwordObject instanceof PasswordBase) {
                return ((PasswordBase) passwordObject).getLocation();
            }
            return null;
        }

        @Override
		protected String getSecondaryString(final Object passwordObject) {
            if (passwordObject instanceof PasswordBase) {
                return ((PasswordBase) passwordObject).getUsername();
            }

            return null;
        }
    }
}
