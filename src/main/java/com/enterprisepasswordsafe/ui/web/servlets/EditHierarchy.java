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
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.List;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.derived.HierarchyNodeChildren;
import com.enterprisepasswordsafe.engine.nodes.NodeManipulator;
import com.enterprisepasswordsafe.ui.web.servlets.authorisation.AccessApprover;
import com.enterprisepasswordsafe.ui.web.servlets.authorisation.UserLevelConditionalConfigurationAccessApprover;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

/**
 * Servlet to direct the user to the hierarchy editing screen.
 */

public final class EditHierarchy extends HttpServlet {
	/**
	 *
	 */
	private static final long serialVersionUID = 5081239248366681865L;

	/**
	 * The access authenticator
	 */

	private static final AccessApprover accessApprover =
		new UserLevelConditionalConfigurationAccessApprover(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);

    /**
     * The action text for an add action.
     */

    public static final String ADD_ACTION = "a";

    /**
     * The action text for a delete action.
     */

    public static final String DELETE_ACTION = "d";

    /**
     * The action text for copying an item.
     */

    public static final String COPY_ACTION = "c";

    /**
     * The action text for copying an item.
     */

    public static final String DEEP_COPY_ACTION = "o";

    /**
     * The action text for cuting an item.
     */

    public static final String CUT_ACTION = "u";

    /**
     * The action text for pasting an item.
     */

    public static final String PASTE_ACTION = "p";


    /**
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    		throws ServletException, IOException {
    	try {
			User user = SecurityUtils.getRemoteUser(request);
			SecurityUtils.isAllowedAccess(accessApprover, user);

		    HierarchyNode node = closestVisibleNodeForUser(request, user);

		    ServletUtils servletUtils = ServletUtils.getInstance();
		    servletUtils.setCurrentNodeId(request, node.getNodeId());

		    String action = request.getParameter(BaseServlet.ACTION_PARAMETER);

		    request.setAttribute("node", node);

		    // Check for movement.
		    String oldNodeId = servletUtils.getNodeId(request);
		    if (oldNodeId != null && !node.getNodeId().equals(oldNodeId)) {
		        action = null;
		    }

		    // Check for an action
		    if (action != null && action.length() > 0) {
		        String nextPage = performAction(request, user, action, node);
		        if (nextPage != null) {
		        	response.sendRedirect(request.getContextPath()+nextPage);
		        	return;
		        }
		    }


		    String hideEmpty = ConfigurationDAO.getValue(ConfigurationOption.HIDE_EMPTY_FOLDERS);
		    boolean includeEmpty = (hideEmpty.equals(Configuration.HIDE_EMPTY_FOLDERS_OFF));
		    if	( user.isSubadministrator() ){
		        String displayEdit = ConfigurationDAO.getValue(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL);
		        if( displayEdit != null && 	displayEdit.equals("S") ) {
		        	includeEmpty = true;
		        }
		    }

		    HierarchyNodeChildren children =
                    HierarchyNodeDAO.getInstance().getChildrenValidForUser(node, user, includeEmpty, null, null);
		    request.setAttribute(BaseServlet.NODE_CHILDREN, children);
		    servletUtils.setCurrentNodeId(request, node.getNodeId());
    	} catch(SQLException | GeneralSecurityException e) {
    		throw new ServletException("There was a problem editing the hierarchy.", e);
    	}
        request.getRequestDispatcher("/subadmin/edit_subnodes.jsp").forward(request, response);
    }

    private HierarchyNode closestVisibleNodeForUser(final HttpServletRequest request, User user)
            throws SQLException, ServletException, GeneralSecurityException {
        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
        HierarchyNode node = getValidNode(request, hnDAO);
        HierarchyNodeAccessRuleDAO hnarDAO = HierarchyNodeAccessRuleDAO.getInstance();
        List<HierarchyNode> parentage = hnDAO.getParentage(node);
        if( !user.isAdministrator()
                &&	hnarDAO.getAccessibilityForUser(node, user) == HierarchyNodeAccessRuleDAO.ACCESIBILITY_DENIED) {
            for( HierarchyNode thisNode : parentage ) {
                if(hnarDAO.getAccessibilityForUser(thisNode, user) == HierarchyNodeAccessRuleDAO.ACCESIBILITY_DENIED) {
                    break;
                }
                node = thisNode;
            }
            ServletUtils.getInstance().generateErrorMessage(request,
                    "You are not allowed access to the folder you requested. You have been diverted to a folder you can access."
            );
            parentage = hnDAO.getParentage(node);
        }
        request.setAttribute(BaseServlet.NODE_PARENTAGE, parentage);
        return node;
    }

    private HierarchyNode getValidNode(final HttpServletRequest request,
                                       final HierarchyNodeDAO hnDAO)
            throws ServletException, SQLException {
        ServletUtils servletUtils = ServletUtils.getInstance();
        String nodeId = servletUtils.getNodeId(request);
        if(nodeId == null) {
            nodeId = HierarchyNode.ROOT_NODE_ID;
        }

        HierarchyNode node = hnDAO.getById(nodeId);
        if(node == null) {
            nodeId = HierarchyNode.ROOT_NODE_ID;
            node = hnDAO.getById(nodeId);
        }

        if( node.getType() == HierarchyNode.USER_CONTAINER_NODE ) {
            throw new ServletException("Access to that node is forbidden.");
        }

        return node;
    }

    /**
     * Edit hierarchy may be posted to with an action, so the post is passed on to the get
     * handler.
     */
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
    		throws ServletException, IOException {
    	doGet(request, response);
    }

    private String performAction(final HttpServletRequest request, final User user, final String action,
                                 final HierarchyNode node)
            throws SQLException, GeneralSecurityException, IOException {
        if (action.equals(EditHierarchy.ADD_ACTION)) {
            return "/subadmin/add_subnode.jsp";
        }

        switch (action) {
            case EditHierarchy.COPY_ACTION:
            case EditHierarchy.DEEP_COPY_ACTION:
            case EditHierarchy.CUT_ACTION: {
                processSelection(request, action, node);
                break;
            }
            case EditHierarchy.PASTE_ACTION: {
                processPaste(request, node);
                break;
            }
            case EditHierarchy.DELETE_ACTION: {
                processDelete(request, user, node);
                break;
            }
        }

        return null;
    }

    private void processSelection(HttpServletRequest request, String action, final HierarchyNode node)
            throws SQLException {
        String[] nodes = request.getParameterValues(BaseServlet.NODE_LIST_PARAMETER);
        if (nodes == null || nodes.length == 0) {
            StringBuilder message = new StringBuilder();
            if (action.equals(EditHierarchy.COPY_ACTION) || action.equals(EditHierarchy.DEEP_COPY_ACTION)) {
                message.append("Copy");
            } else if (action.equals(EditHierarchy.CUT_ACTION)) {
                message.append("Cut");
            }
            message.append(" failed, No items were selected.");
            ServletUtils.getInstance().generateErrorMessage(request, message.toString());
            return;
        }

        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
        for (int i = 0; i < nodes.length; i++) {
            String thisNode = nodes[i];
            if (thisNode.startsWith("p_")) {
                String passwordId = thisNode.substring(2);
                nodes[i] = hnDAO.getNodeIDForObject(node.getNodeId(), passwordId);
            }
        }

        HttpSession session = request.getSession();
        session.setAttribute(BaseServlet.ACTION_PARAMETER, action);
        session.setAttribute(BaseServlet.NODE_LIST_PARAMETER, nodes);

        ServletUtils.getInstance().generateMessage(
                request, generateOperationSuccessMessage(action, nodes.length > 1));
    }

    private String generateOperationSuccessMessage(String action, boolean isForMultiple) {
        StringBuilder message = new StringBuilder();
        message.append("The selected item");
        message.append(isForMultiple ? "s have" : " has");
        message.append(" been ");
        if (action.equals(EditHierarchy.COPY_ACTION) || action.equals(EditHierarchy.DEEP_COPY_ACTION)) {
            message.append("copied.");
        } else {
            message.append("cut.");
        }
        return message.toString();
    }

    private void processPaste(final HttpServletRequest request, final HierarchyNode node)
            throws GeneralSecurityException, SQLException {
        HttpSession session = request.getSession();
        String sessonAction = (String) session.getAttribute(BaseServlet.ACTION_PARAMETER);
        String[] nodes = (String[]) session.getAttribute(BaseServlet.NODE_LIST_PARAMETER);
        if (sessonAction != null && nodes != null && nodes.length > 0) {
            HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
            switch (sessonAction) {
                case EditHierarchy.COPY_ACTION:
                    pasteCopiedNodes(hnDAO, node, nodes);
                    break;
                case EditHierarchy.DEEP_COPY_ACTION:
                    pasteDeepCopiedNodes(hnDAO, node, nodes);
                    break;
                case EditHierarchy.CUT_ACTION:
                    pasteCutNodes(hnDAO, node, nodes);
                    break;
                default:
                    ServletUtils.getInstance().generateErrorMessage(request, "The items selected were not copied or pasted.");
                    break;
            }
        } else {
            ServletUtils.getInstance().generateErrorMessage(request, "Paste failed. No items have been cut or copied.");
        }

        session.removeAttribute(BaseServlet.ACTION_PARAMETER);
        session.removeAttribute(BaseServlet.NODE_LIST_PARAMETER);
    }

    private void processDelete(final HttpServletRequest request, final User viewingUser, final HierarchyNode node)
            throws SQLException, GeneralSecurityException, IOException {
        String[] nodes = request.getParameterValues(BaseServlet.NODE_LIST_PARAMETER);
        if (nodes == null || nodes.length == 0) {
            ServletUtils.getInstance().generateErrorMessage(request, "Delete failed, No items were selected.");
            return;
        }

        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
        // TODO : Check permissions of subnodes, and block if
        // the user can not access a specific subnode.
        for (String thisNodeId : nodes) {
            // Skip deletiong of any non-existant nodes
            if (thisNodeId != null && thisNodeId.startsWith("p_")) {
                thisNodeId = hnDAO.getNodeIDForObject(node.getNodeId(), thisNodeId.substring(2));
            }
            if (thisNodeId == null) {
                continue;
            }
            HierarchyNode thisNode = hnDAO.getById(thisNodeId);
            if (thisNode == null) {
                continue;
            }

            if (isNotDeletableByUser(viewingUser, thisNode)) {
                ServletUtils.getInstance().generateErrorMessage(request,
                        "Delete failed, You do not have the permissions needed to delete all the objects specified.");
                return ;
            }
        }

        // Now the permissions have been checked we can perform the delete.
        for (String thisNodeId : nodes) {
            if (thisNodeId != null && thisNodeId.startsWith("p_")) {
                thisNodeId = hnDAO.getNodeIDForObject(node.getNodeId(), thisNodeId.substring(2));
            }
            if (thisNodeId == null) {
                continue;
            }

            HierarchyNode thisNode = hnDAO.getById(thisNodeId);
            if (thisNode != null) {
                hnDAO.deleteNode(thisNode, viewingUser);
            }
        }
    }

    private boolean isNotDeletableByUser(final User user, final HierarchyNode node)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if(node.getType() == HierarchyNode.OBJECT_NODE) {
            AccessControl ac = AccessControlDAO.getInstance().getAccessControl(user, node.getName());
            return (ac != null && ac.getModifyKey() != null);
        }

        for(HierarchyNode thisNode : HierarchyNodeDAO.getInstance().getAllChildren(node)) {
            if(isNotDeletableByUser(user,thisNode)) {
                return false;
            }
        }

        return true;
    }

    private void pasteCutNodes(final HierarchyNodeDAO hnDAO, final HierarchyNode newParent, final String[] nodes)
            throws SQLException, GeneralSecurityException {
        runManipulatorOnNodes(hnDAO, newParent, nodes, new NodeManipulator.MoveNodeManipulator(hnDAO));
    }

    private void pasteCopiedNodes(final HierarchyNodeDAO hnDAO, final HierarchyNode newParent, final String[] nodes)
        throws SQLException, GeneralSecurityException {
        runManipulatorOnNodes(hnDAO, newParent, nodes, new NodeManipulator.CopyNodeManipulator(hnDAO));
    }

    private void pasteDeepCopiedNodes(final HierarchyNodeDAO hnDAO, final HierarchyNode newParent,
                                      final String[] nodes)
        throws SQLException, GeneralSecurityException {
        runManipulatorOnNodes(hnDAO, newParent, nodes, new NodeManipulator.DeepCopyNodeManipulator(hnDAO));
    }

    private void runManipulatorOnNodes(final HierarchyNodeDAO hnDAO, final HierarchyNode node, final String[] nodes,
                                       NodeManipulator nodeManipulator)
            throws GeneralSecurityException, SQLException {
        for(String nodeId : nodes) {
            if (nodeId == null) {
                continue;
            }

            HierarchyNode theNode = hnDAO.getById(nodeId);
            if (theNode != null) {
                nodeManipulator.performAction(theNode, node);
            } else {
                log("Unable to work on node " + nodeId + " - Node was unavailable.");
            }
        }
    }

    @Override
	public String getServletInfo() {
        return "Allows the editing of a node in the hierarchy";
    }
}
