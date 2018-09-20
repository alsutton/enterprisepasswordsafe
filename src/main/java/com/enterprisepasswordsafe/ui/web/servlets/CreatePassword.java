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

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.hierarchy.HierarchyTools;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Map;
import java.util.TreeMap;

public final class CreatePassword extends HttpServlet {

	private final UserClassifier userClassifier = new UserClassifier();

	private HierarchyTools hierarchyTools = new HierarchyTools();

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	final ServletUtils servletUtils = ServletUtils.getInstance();

        String nodeId = servletUtils.getNodeId(request);
        if( nodeId == null ) {
        	nodeId = HierarchyNode.ROOT_NODE_ID;
        }

        try {
	        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
	        HierarchyNode node = hnDAO.getById(nodeId);

	        User theUser = SecurityUtils.getRemoteUser(request);

	        boolean accessApproved = true;
	        if( !userClassifier.isPriviledgedUser(theUser) ) {
	        	if( node.getType() == HierarchyNode.USER_CONTAINER_NODE
	        	&& !node.getNodeId().equals(theUser.getUserId())) {
	        		accessApproved = false;
	        	}
	        }

	        if( !accessApproved ) {
	        	throw new ServletException("You can not create passwords in that area.");
	        }

	        Calendar cal = Calendar.getInstance();
	        Integer year = cal.get(Calendar.YEAR);
	        request.setAttribute("year", year);

	        ConfigurationDAO cDAO = ConfigurationDAO.getInstance();

	        request.setAttribute("enabled", "y");
	        request.setAttribute(BaseServlet.NODE, node);
	        request.setAttribute(BaseServlet.NODE_PARENTAGE, hierarchyTools.getParentageAsText(node));
	        request.setAttribute("password_history",cDAO.get(ConfigurationOption.STORE_PASSWORD_HISTORY));
	        request.setAttribute("password_audit",cDAO.get(ConfigurationOption.PASSWORD_AUDIT_LEVEL));

	        request.setAttribute(
	                ConfigurationOption.HIDDEN_PASSWORD_ENTRY.getPropertyName(),
	                cDAO.get(ConfigurationOption.HIDDEN_PASSWORD_ENTRY)
	            );

	        PasswordRestrictionDAO prDAO = PasswordRestrictionDAO.getInstance();
	        request.setAttribute("restriction_list", prDAO.getAll());

	    	String hideLocations = cDAO.get(ConfigurationOption.PASSWORD_HIDE_SYSTEM_SELECTOR);
	    	if( hideLocations == null || hideLocations.charAt(0) == 'n') {
		    	request.setAttribute("locations_set", LocationDAO.getInstance().getAll());
	    	}

	    	String passwordFieldType = "password";
	    	String hiddenPassword = cDAO.get(ConfigurationOption.HIDDEN_PASSWORD_ENTRY);
	    	if( hiddenPassword.equalsIgnoreCase("false") ) {
	    		passwordFieldType="text";
	    	}
	    	request.setAttribute("passwordFieldType", passwordFieldType);

	    	//
	    	// Copy any values from the incoming request so they stay on the page.
	    	//
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


	    	String restrictionId = request.getParameter("restriction.id");
	    	String restrictionName = null;
	    	if(restrictionId != null && ! restrictionId.isEmpty()) {
	    		PasswordRestriction restriction = prDAO.getById(restrictionId);
	    		if( restriction != null ) {
	    			restrictionName = restriction.getName();
	    		}
	    	}
	    	if( restrictionName != null ) {
	    		request.setAttribute("restriction_id", restrictionId);
	    		request.setAttribute("restriction_name", restrictionName);
	    	} else {
	    		request.setAttribute("restriction_id", "");
	    	}

	    	if( request.getAttribute("cfields") == null ) {
	    		Map<String,String> customFields = new TreeMap<>();
		    	int i = 0;
		    	String fieldName, fieldValue;
		    	while( (fieldName = cDAO.get("custom_fn"+i, null)) != null ) {
		    		fieldValue = cDAO.get("custom_fv"+i, "");
		    		customFields.put(fieldName, fieldValue);
		    		i++;
		    	}
		        request.setAttribute("cfields", customFields);
	    	}
        } catch(SQLException sqle) {
        	throw new ServletException("There was an error preparing for the password creation", sqle);
        }

    	request.getRequestDispatcher("/subadmin/new_password.jsp").forward(request, response);
    }

    /**
     * This can be POSTed to, so chain doPost into doGet
     */

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	doGet(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Directs the user to the password creation page";
    }

}
