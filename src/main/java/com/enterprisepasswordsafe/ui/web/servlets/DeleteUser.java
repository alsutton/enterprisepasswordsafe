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

import com.enterprisepasswordsafe.engine.database.TamperproofEventLog;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLogDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.database.UserDAO;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

/**
 * Deletes a user whose id has been passed in the ID parameter.
 */

public final class DeleteUser extends HttpServlet {
    /**
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */

	@Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {

        try {
            User thisUser = SecurityUtils.getRemoteUser(request);
            if(!thisUser.isAdministrator()) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            String userId = request.getParameter("id");
            if(userId == null || userId.isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            ServletUtils servletUtils = ServletUtils.getInstance();

            UserDAO uDAO = UserDAO.getInstance();
            User theUser = uDAO.getById(userId);
            if(theUser == null) {
                servletUtils.generateErrorMessage(request, "The user could not be found.");
            } else {
                UserDAO.getInstance().delete(theUser);
                servletUtils.generateMessage(request, "The user " + theUser + " has been deleted");
                TamperproofEventLogDAO.getInstance().create(
                        TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
                        thisUser,
                        null,
                        "Deleted the user {user:" + theUser.getUserId() + "}",
                        true
                );
            }
        } catch (GeneralSecurityException e) {
            throw new ServletException(e);
        } catch (SQLException sqle) {
            throw new ServletException(sqle);
        }

        response.sendRedirect(request.getContextPath()+"/admin/ViewUsers");
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Delete the specified user";
    }

}
