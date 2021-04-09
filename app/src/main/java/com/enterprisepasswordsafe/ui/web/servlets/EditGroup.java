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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Servlet to get the information relating to a group to be edited.
 */

public final class EditGroup extends HttpServlet {

    /**
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response)
        throws ServletException, IOException {
        String id = request.getParameter("id");

        GroupStoreManipulator gDAO = UnfilteredGroupDAO.getInstance();
        UserDAO userDAO = UserDAO.getInstance();
        try {
	        Group group = gDAO.getById(id);
	        request.setAttribute("group", group);

	        if( group.isEnabled() ) {
	            List<User> members = userDAO.getGroupMembers(group);
	            List<User> nonMembers = new ArrayList<>(UserDAO.getInstance().getEnabledUsers());
	            nonMembers.removeAll(members);

	            Collections.sort(members);
	            Collections.sort(nonMembers);

		        request.setAttribute("group_members", members);
		        request.setAttribute("membercount", Integer.toString(members.size()));
		        request.setAttribute("group_nonMembers", nonMembers);
	        }
        } catch(SQLException sqle) {
        	throw new ServletException("There was a problem obtaining the password details.", sqle);
        }

        request.getRequestDispatcher("/admin/edit_group.jsp").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Servlet to get the information about a group to be edited";
    }
}
