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
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Comparator;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.derived.HierarchyNodeChildren;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Handles the user interacting with the password hierarchy.
 */

public final class Explorer extends HttpServlet {

    /**
     * @throws UnsupportedEncodingException
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
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
	        HierarchyNode node = hnDAO.getById(nodeId);
	        if(node == null) {
	        	nodeId = HierarchyNode.ROOT_NODE_ID;
	        	node = hnDAO.getById(nodeId);
	        }

	        if( node.getType() == HierarchyNode.USER_CONTAINER_NODE ) {
	        	nodeId = HierarchyNode.ROOT_NODE_ID;
	        	node = hnDAO.getById(nodeId);
	        }

	        List<HierarchyNode> parentage = hnDAO.getParentage(node);
	        HierarchyNodeAccessRuleDAO hnarDAO = HierarchyNodeAccessRuleDAO.getInstance();
	        if( !user.isAdministrator()
	        &&	hnarDAO.getAccessibilityForUser(node, user)
					== HierarchyNodeAccessRuleDAO.ACCESIBILITY_DENIED) {
	        	for(HierarchyNode thisNode : parentage) {
		        	if(hnarDAO.getAccessibilityForUser(thisNode, user)
		    				== HierarchyNodeAccessRuleDAO.ACCESIBILITY_DENIED) {
		        		break;
		        	}
		        	node = thisNode;
	        	}
	        	su.generateErrorMessage(
	        			request,
	        			"You are not allowed access to the folder you requested. "+
	        			"You have been diverted to a folder you can access."
	        		);
	        	parentage = hnDAO.getParentage(node);
	        }
	        su.setCurrentNodeId(request, node.getNodeId());

	    	su.setCurrentNodeId(request, nodeId);
	        boolean includeEmpty =
					ConfigurationDAO.
							getValue(ConfigurationOption.HIDE_EMPTY_FOLDERS).
							equals(Configuration.HIDE_EMPTY_FOLDERS_OFF);

	        request.setAttribute("edithierarchy_allowed", "N");
            if(!user.isNonViewingUser()) {
                if			( user.isAdministrator() ) {
                    request.setAttribute("edithierarchy_allowed", "Y");
                } else if	( user.isSubadministrator() ){
                    String displayEdit = ConfigurationDAO.getValue(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);
                    if( displayEdit != null && 	displayEdit.equals("S") ) {
                        request.setAttribute("edithierarchy_allowed", "Y");
                        includeEmpty = true;
                    }
                }
            }

	        HttpSession session = request.getSession(false);
	        String sortOrder = request.getParameter(BaseServlet.SORT_PARAMETER);
	        if (sortOrder == null) {
	            sortOrder = (String) session.getAttribute(BaseServlet.SORT_PARAMETER);
	        }
	        Comparator<Password> objectComparator;
	        if (sortOrder != null && sortOrder.startsWith("S")) {
	        	objectComparator = new SystemComparator();
	        } else {
	            objectComparator = new UsernameComparator();
	        }

	        HierarchyNodeChildren children = hnDAO.getChildrenValidForUser(node, user, includeEmpty, null, objectComparator);
            if(user.isNonViewingUser()) {
                children.setObjects(null);
            }

	        session.setAttribute(BaseServlet.SORT_PARAMETER, sortOrder);
	        su.setCurrentNodeId(request, nodeId);

	        request.setAttribute(BaseServlet.NODE, node);
	        request.setAttribute(BaseServlet.NODE_PARENTAGE, parentage);
	        request.setAttribute(BaseServlet.NODE_CHILDREN, children);
        } catch( GeneralSecurityException sqle ) {
        	throw new ServletException("The password explorer encountered an error.", sqle);
        } catch( SQLException sqle ) {
        	throw new ServletException("The password explorer encountered an error.", sqle);
        }
        request.getRequestDispatcher("/system/view_subnodes.jsp").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Obtains and displays the information about a node in the hierarchy";
    }

    /**
     * Base Comparitor for two passwords.
     */

    private abstract class PasswordComparator implements Comparator<Password>, Serializable {
        /**
		 *
		 */
		private static final long serialVersionUID = -2072081239990481472L;

		/**
         * Get the username from a password or password summary.
         *
         * @param passwordObject
         *            The Password or Password.Summary object
         *
         * @return The string to compare.
         */

        protected abstract String getKeyString(Object passwordObject) throws Exception;

        /**
         * Get the username from a password or password summary.
         *
         * @param passwordObject
         *            The Password or Password.Summary object
         *
         * @return The string to compare.
         */

        protected abstract String getSecondaryString(Object passwordObject) throws Exception;

        /**
         * Extract the key string from a Password or Password.Summary object and
         * compare.
         *
         * @param passwordObject0
         *            The Password or Password.Summary object.
         * @param passwordObject1
         *            The other Password or Password.Summary object.
         *
         * @return < 0 if passwordObject0 is less than passwordObject1, 0 if the
         *  two are equal, or > 0 if passwordObject0 is greater than passwordObject1.
         */
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

	            String key0 = getKeyString(passwordObject0);
	            String key1 = getKeyString(passwordObject1);
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

	            key0 = getSecondaryString(passwordObject0);
	            key1 = getSecondaryString(passwordObject1);
	            if (key0 == null) {
	                return Integer.MIN_VALUE;
	            }
	            if (key1 == null) {
	                return Integer.MAX_VALUE;
	            }

	            caseInsensitiveComparison = key0.compareToIgnoreCase(key1);
	            if (caseInsensitiveComparison != 0) {
	            	return caseInsensitiveComparison;
	            }
	            caseSensitiveComparison = key0.compareTo(key1);
	        	if( caseSensitiveComparison != 0 ) {
	        		return caseSensitiveComparison;
	        	}

	            return passwordObject0.getId().compareTo(passwordObject1.getId());
        	} catch( Exception ex ) {
        		throw new RuntimeException(ex);
        	}
        }
    }

    /**
     * Class to compare passwords based on the username.
     */

    private class UsernameComparator extends PasswordComparator {
        /**
		 *
		 */
		private static final long serialVersionUID = -5621430270656996999L;

		/**
         * Get the username from a password or password summary.
         *
         * @param passwordObject
         *            The Password or Password.Summary object to extract the
         *            username from.
         *
         * @return The username
		 * @throws GeneralSecurityException
		 * @throws UnsupportedEncodingException
         */

        @Override
		protected String getKeyString(final Object passwordObject) throws UnsupportedEncodingException, GeneralSecurityException {
            if (passwordObject instanceof PasswordBase) {
                return ((PasswordBase) passwordObject).getUsername();
            }
            return null;
        }

        /**
         * Get the location from a password or password summary.
         *
         * @param passwordObject
         *            The Password or Password.Summary object to extract the
         *            location from.
         *
         * @return The username
         */

        @Override
		protected String getSecondaryString(final Object passwordObject) {
            if (passwordObject instanceof PasswordBase) {
                return ((PasswordBase) passwordObject).getLocation();
            }

            return null;
        }
    }

    /**
     * Class to compare passwords based on the system.
     */

    private class SystemComparator extends PasswordComparator {
        /**
		 *
		 */
		private static final long serialVersionUID = 1821016630814778167L;

		/**
         * Get the location from a password or password summary.
         *
         * @param passwordObject
         *            The Password or Password.Summary object to extract the
         *            location from.
         *
         * @return The username
         */

        @Override
		protected String getKeyString(final Object passwordObject) {
            if (passwordObject instanceof PasswordBase) {
                return ((PasswordBase) passwordObject).getLocation();
            }
            return null;
        }

        /**
         * Get the username from a password or password summary.
         *
         * @param passwordObject
         *            The Password or Password.Summary object to extract the
         *            username from.
         *
         * @return The username
         * @throws GeneralSecurityException
         * @throws UnsupportedEncodingException
         */

        @Override
		protected String getSecondaryString(final Object passwordObject) throws UnsupportedEncodingException, GeneralSecurityException {
            if (passwordObject instanceof PasswordBase) {
                return ((PasswordBase) passwordObject).getUsername();
            }

            return null;
        }
    }
}
