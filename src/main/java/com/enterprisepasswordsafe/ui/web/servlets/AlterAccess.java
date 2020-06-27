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
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;


public final class AlterAccess extends HttpServlet {

	private final UserClassifier userClassifier = new UserClassifier();

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
        String passwordId = ServletUtils.getInstance().getParameterValue(request, "id");
        try {
	        User thisUser = SecurityUtils.getRemoteUser(request);
	        if (!userClassifier.isPriviledgedUser(thisUser)) {
	            throw new ServletException("You can not modify access to this password");
	        }

	        Password thisPassword = UnfilteredPasswordDAO.getInstance().getById(thisUser, passwordId);

	        GroupDAO gDAO = GroupDAO.getInstance();
	        Group everyoneGroup = gDAO.getByIdDecrypted(Group.ALL_USERS_GROUP_ID, thisUser);
	        AccessControl eGAC =
	        	GroupAccessControlDAO.getInstance().getGac(thisUser, everyoneGroup, thisPassword);
	        if			( eGAC == null ) {
	        	request.setAttribute("egac", "N");
	        } else if	( eGAC.getReadKey() != null && eGAC.getModifyKey() == null) {
	        	request.setAttribute("egac", "R");
	        } else if	( eGAC.getReadKey() != null) {
	        	request.setAttribute("egac", "RM");
	        }

	        request.setAttribute(SharedParameterNames.PASSWORD_ATTRIBUTE, thisPassword);
	        request.setAttribute( "gac_summaries", GroupAccessControlDAO.getInstance().getSummaries(thisPassword));
	        request.setAttribute( "uac_summaries", UserAccessControlDAO.getInstance().getSummaries(thisPassword));
        } catch(SQLException | GeneralSecurityException e) {
        	throw new ServletException("The access information could not be obtained due to an error", e);
        }

        request.getRequestDispatcher("/subadmin/edit_access.jsp").forward(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Directs the user to the screen which alters a passwords accessibility.";
    }

}
