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

import com.enterprisepasswordsafe.engine.hierarchy.HierarchyTools;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.utils.PasswordRestrictionUtils;
import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.dao.ConfigurationDAO;
import com.enterprisepasswordsafe.model.dao.HierarchyNodeDAO;
import com.enterprisepasswordsafe.model.dao.LocationDAO;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.ui.web.password.CustomFieldPopulator;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Calendar;

public final class CreatePassword extends HttpServlet {

	private final UserClassifier userClassifier = new UserClassifier();

	private final HierarchyTools hierarchyTools = new HierarchyTools();
	private final ServletUtils servletUtils = new ServletUtils();

	private final ConfigurationDAO configurationDAO = ConfigurationDAO.getInstance();

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        try {
	        HierarchyNode node = getNode(request);
	        ensureUserCanCreatePasswordInNode(request, node);
            request.setAttribute(BaseServlet.NODE, node);
            request.setAttribute(BaseServlet.NODE_PARENTAGE, hierarchyTools.getParentageAsText(node));

	        Calendar cal = Calendar.getInstance();
	        Integer year = cal.get(Calendar.YEAR);
	        request.setAttribute("year", year);
	        request.setAttribute("enabled", "y");
	        addLocationsIfAllowed(request);
            setPasswordFieldType(request);
            copyParametersToAttributes(request);
            setPropertiesFromSystemConfiguration(request);
            setRestrictionAttributes(request);
            setCustomFields(request);
        } catch(SQLException sqle) {
        	throw new ServletException("There was an error preparing for the password creation", sqle);
        }

    	request.getRequestDispatcher("/subadmin/new_password.jsp").forward(request, response);
    }

    private void ensureUserCanCreatePasswordInNode(HttpServletRequest request, HierarchyNode node)
            throws ServletException, SQLException {
        User theUser = SecurityUtils.getRemoteUser(request);
        if( userClassifier.isPriviledgedUser(theUser) ) {
            return;
        }
        if( node.getType() == HierarchyNode.USER_CONTAINER_NODE && !node.getNodeId().equals(theUser.getId())) {
            throw new ServletException("You can not create passwords in that area.");
        }
    }

    private HierarchyNode getNode(HttpServletRequest request)
            throws SQLException {
        String nodeId = servletUtils.getNodeId(request);
        nodeId = nodeId == null ? HierarchyNode.ROOT_NODE_ID : nodeId;
        return HierarchyNodeDAO.getInstance().getById(nodeId);
	}

	private void addLocationsIfAllowed(HttpServletRequest request)
            throws SQLException {
        String hideLocations = configurationDAO.get(ConfigurationOptions.PASSWORD_HIDE_SYSTEM_SELECTOR);
        if( hideLocations == null || hideLocations.charAt(0) == 'n') {
            request.setAttribute("locations_set", LocationDAO.getInstance().getAll());
        }
    }

	private void setPropertiesFromSystemConfiguration(HttpServletRequest request)
            throws SQLException {
        request.setAttribute("password_history",
                configurationDAO.get(ConfigurationOptions.STORE_PASSWORD_HISTORY));
        request.setAttribute("password_audit",
                configurationDAO.get(ConfigurationOptions.PASSWORD_AUDIT_LEVEL));
        request.setAttribute(ConfigurationOptions.HIDDEN_PASSWORD_ENTRY.getPropertyName(),
                configurationDAO.get(ConfigurationOptions.HIDDEN_PASSWORD_ENTRY));
    }

	private void copyParametersToAttributes(HttpServletRequest request) {
        servletUtils.copyParameterToAttribute(request, "username");
        servletUtils.copyParameterToAttribute(request, "password_1");
        servletUtils.copyParameterToAttribute(request, "password_2");
        servletUtils.copyParameterToAttribute(request, "location_text");
        servletUtils.copyParameterToAttribute(request, "enabled");
        servletUtils.copyParameterToAttribute(request, "expiry");
        servletUtils.copyParameterToAttribute(request, "ra_enabled");
        servletUtils.copyParameterToAttribute(request, "ra_approvers");
        servletUtils.copyParameterToAttribute(request, "ra_blockers");
        servletUtils.copyParameterToAttribute(request, "audit", "F");
        servletUtils.copyParameterToAttribute(request, "history");
        servletUtils.copyParameterToAttribute(request, "notes");
    }

    private void setPasswordFieldType(HttpServletRequest request)
            throws SQLException {
        String passwordFieldType = "password";
        String hiddenPassword = configurationDAO.get(ConfigurationOptions.HIDDEN_PASSWORD_ENTRY);
        if( hiddenPassword.equalsIgnoreCase("false") ) {
            passwordFieldType="text";
        }
        request.setAttribute("passwordFieldType", passwordFieldType);
    }

    private void setCustomFields(HttpServletRequest request)
            throws SQLException {
        if( request.getAttribute("cfields") == null ) {
            new CustomFieldPopulator().populateRequestWithDefaultCustomFields(request);
        }
    }

    private void setRestrictionAttributes(HttpServletRequest request)
            throws SQLException {
        PasswordRestrictionDAO prDAO = PasswordRestrictionDAO.getInstance();
        request.setAttribute("restriction_list", prDAO.getAll());

        PasswordRestrictionUtils restriction = findRelevantRestriction(request, prDAO);
        if( restriction == null ) {
            request.setAttribute("restriction_id", "");
            return;
        }
        request.setAttribute("restriction_id", restriction.getId());
        request.setAttribute("restriction_name", restriction.getName());
    }

    private PasswordRestrictionUtils findRelevantRestriction(final HttpServletRequest request,
                                                             final PasswordRestrictionDAO passwordRestrictionDAO)
            throws SQLException {
        String restrictionId = request.getParameter("restriction.id");
        if(restrictionId == null || restrictionId.isEmpty()) {
            return null;
        }
        return passwordRestrictionDAO.getById(restrictionId);
    }

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	doGet(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Directs the user to the password creation page";
    }

}
