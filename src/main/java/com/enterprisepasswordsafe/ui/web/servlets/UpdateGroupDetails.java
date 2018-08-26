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

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

public final class UpdateGroupDetails extends HttpServlet {

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	try {
	        User user = SecurityUtils.getRemoteUser(request);

	        GroupStoreManipulator gDAO = UnfilteredGroupDAO.getInstance();
	        String groupId = request.getParameter("group_id");
	        Group group = gDAO.getById(groupId);

	        Membership membership = MembershipDAO.getInstance().getMembership(user, group);
	        group.updateAccessKey(membership);

	        group.setGroupName(request.getParameter("name"));

	        String enabledFlag = request.getParameter("enabled");
	        if(enabledFlag != null && enabledFlag.charAt(0) == 'Y') {
	        	group.setStatus(Group.STATUS_ENABLED);
	        } else {
	        	group.setStatus(Group.STATUS_DISABLED);
	        }

	        gDAO.update(group);

	        ServletUtils.getInstance().generateMessage(request, "The group information has been updated.");

	        response.sendRedirect(request.getContextPath()+"/admin/EditGroup?id="+groupId);
    	} catch(SQLException | GeneralSecurityException ex) {
    		throw new ServletException("There was a problem updating the group.", ex);
    	}
    }

    @Override
	public String getServletInfo() {
        return "Servlet to alter a the details about a group.";
    }

}
