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
import com.enterprisepasswordsafe.model.dao.GroupDAO;
import com.enterprisepasswordsafe.model.dao.MembershipDAO;
import com.enterprisepasswordsafe.model.dao.UserDAO;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Servlet to direct the user to the page allowing them to alter their login
 * password.
 */

public final class ApplyUpgrades extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = 5587012613516551053L;


    /**
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doGet( final HttpServletRequest request, final HttpServletResponse response)
    	throws IOException, ServletException {

    	User adminUser = SecurityUtils.getRemoteUser(request);
    	GroupDAO groupDAO = GroupDAO.getInstance();
    	try {
	    	if( !groupDAO.idExists(Group.ALL_USERS_GROUP_ID)) {
	        	Group adminGroup = groupDAO.getAdminGroup(adminUser);
	    		Group theGroup = groupDAO.create(adminUser, Group.ALL_USERS_GROUP_ID, "All Users");

	    		MembershipDAO membershipDAO = MembershipDAO.getInstance();
	    		for(User thisUser : UserDAO.getInstance().getAll()) {
	    			try {
		    			thisUser.decryptAdminAccessKey(adminGroup);
		    			membershipDAO.create(thisUser, theGroup);
	    			} catch( Exception ex ) {
	    				Logger.getAnonymousLogger().log(
	    						Level.WARNING,
	    						"Error adding "+thisUser.getId()+" to all users group",
	    						ex);
	    			}
	    		}
	    	}

            if(!groupDAO.idExists(Group.NON_VIEWING_GROUP_ID)) {
                groupDAO.write(new Group(Group.NON_VIEWING_GROUP_ID, "Non-viewing Users", true));
            }
    	} catch(SQLException | GeneralSecurityException sqle) {
    		throw new ServletException("The upgrades could not be performed", sqle);
    	}

        ServletUtils.getInstance().generateMessage(request, "The upgrades have been performed");
        request.getRequestDispatcher(ServletPaths.getExplorerPath()).forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Directs the user to the update login password screen";
    }

}
