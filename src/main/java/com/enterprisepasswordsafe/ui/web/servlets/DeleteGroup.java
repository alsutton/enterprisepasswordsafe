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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.Group;
import com.enterprisepasswordsafe.engine.database.GroupDAO;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLog;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLogDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Gets the details of a user to be edited.
 */

public final class DeleteGroup extends HttpServlet {
    /**
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
        request.setAttribute("error_page", "/admin/ViewGroups");

        try {
            User thisUser = SecurityUtils.getRemoteUser(request);
            if(!thisUser.isAdministrator()) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            String groupId = request.getParameter("id");
            if (groupId == null) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

	        GroupDAO gDAO = GroupDAO.getInstance();
            Group theGroup = gDAO.getByIdEvenIfDisabled(groupId);

            ServletUtils servletUtils = ServletUtils.getInstance();
            if (theGroup == null) {
                servletUtils.generateErrorMessage(request, "The group could not be found.");
            } else {
                String groupName = theGroup.getGroupName();
                gDAO.delete(theGroup);
                TamperproofEventLogDAO.getInstance().create(
                        TamperproofEventLog.LOG_LEVEL_GROUP_MANIPULATION,
                        thisUser,
                        null,
                        "Deleted the group {group:" + theGroup.getGroupId() + "}",
                        true
                    );
                ServletUtils.getInstance().generateMessage(request, "The group " + groupName + " has been deleted");
	        }
        } catch(SQLException sqle) {
        	throw new ServletException("The user details are unavailable due to an error.", sqle);
        } catch(GeneralSecurityException gse) {
        	throw new ServletException("The user details are unavailable due to an error.", gse);
        }

        response.sendRedirect(request.getContextPath() + "/admin/ViewGroups");
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Deletes the specified group.";
    }

}
