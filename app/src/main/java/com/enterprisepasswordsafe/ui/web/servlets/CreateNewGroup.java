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

import com.enterprisepasswordsafe.database.Group;
import com.enterprisepasswordsafe.model.dao.GroupDAO;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Servlet to create a new group.
 */

public final class CreateNewGroup extends HttpServlet {

    /**
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException {
    	String groupname = request.getParameter("groupname");
        GroupDAO gDAO = GroupDAO.getInstance();

        try {
            if (gDAO.getByName(groupname) != null) {
                throw new ServletException( "A group with the name '" + groupname + "' already exists.");
            }

            User thisUser = SecurityUtils.getRemoteUser(request);

            Group newGroup = gDAO.create(thisUser, groupname);
            ServletUtils.getInstance().generateMessage(request, "The group was successfully created.");

            response.sendRedirect(request.getContextPath()+"/admin/EditGroup?id="+newGroup.getGroupId());
        } catch (Exception e) {
            log("Error trying to create a new group", e);
            ServletUtils.getInstance().generateErrorMessage(request, "There was a problem creating the group.", e);
            response.sendRedirect(request.getContextPath()+"/admin/CreateGroup");
        }
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Creates a new group";
    }

}
