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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.HierarchyNode;
import com.enterprisepasswordsafe.engine.database.HierarchyNodeDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Servlet to alter the event email settings.
 */

public final class ViewPersonalFolder extends HttpServlet {
    /**
	 *
	 */
	private static final long serialVersionUID = 411859900127257878L;

    /**
     * @throws UnsupportedEncodingException
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletRequest)
     */
    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    	throws IOException, ServletException {
    	try {
	        User thisUser = SecurityUtils.getRemoteUser(request);

	        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
	        HierarchyNode node = hnDAO.getPersonalNodeForUser(thisUser);
	        if( node == null ) {
	        	node = hnDAO.create(thisUser.getUserId(), null,	HierarchyNode.USER_CONTAINER_NODE);
	        }

	        ServletUtils.getInstance().setCurrentNodeId(request, node.getNodeId());

	        request.setAttribute("objects", hnDAO.getAllChildrenObjects(node, thisUser, null));
	        request.getRequestDispatcher("/system/view_personal.jsp").forward(request, response);
    	} catch(Exception ex) {
    		throw new ServletException("Your personal passwords are not available at the current time", ex);
    	}
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Servlet to take the user to their personal passwords page.";
    }
}
