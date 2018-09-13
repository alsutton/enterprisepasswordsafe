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
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.enterprisepasswordsafe.engine.database.Group;
import com.enterprisepasswordsafe.engine.database.GroupDAO;
import com.enterprisepasswordsafe.engine.database.PasswordDAO;
import com.enterprisepasswordsafe.engine.database.PasswordRestriction;
import com.enterprisepasswordsafe.engine.database.PasswordRestrictionDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;

/**
 * Servlet to direct the user to the correct page upon login.
 */

public final class Welcome extends PasswordSafeBaseServlet {

    /**
     * The expiring passwords page.
     */

    private static final String EXPIRING_PASSWORDS_PAGE = "/system/ExpiringPasswords";

    /**
     * The page users are sent to if their password has expired.
     */

    private static final String FORCED_CHANGE_PASSWORD = "/nomenu/Profile";

    private UserClassifier userClassifier = new UserClassifier();

	@Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	// Check to see if the login screen was a diversion from
    	// the original request.
    	HttpSession session = request.getSession();
    	String originalURI = (String) session.getAttribute(BaseServlet.ORIGINAL_URI);
    	if( originalURI != null ) {
    		session.removeAttribute(BaseServlet.ORIGINAL_URI);

    		StringBuilder urlBuffer = new StringBuilder(originalURI);
    		@SuppressWarnings("unchecked")
			Map<Object, Object> params = (Map<Object, Object>)session.getAttribute(BaseServlet.ORIGINAL_PARAMETERS);
    		if( params != null ) {
    			session.removeAttribute(BaseServlet.ORIGINAL_PARAMETERS);
    			urlBuffer.append('?');
    			for(Map.Entry<Object, Object> thisEntry : params.entrySet()) {
    				urlBuffer.append(thisEntry.getKey().toString());
    				urlBuffer.append('=');
    				urlBuffer.append(thisEntry.getValue().toString());
    				urlBuffer.append('&');
    			}
    			urlBuffer.deleteCharAt(urlBuffer.length()-1);
    		}
    		response.sendRedirect(response.encodeRedirectURL(urlBuffer.toString()));
    		return;
    	}

    	try {
	        User thisUser = SecurityUtils.getRemoteUser(request);

	        // Check if the users password has expired
			long passwordLastChanged = thisUser.getPasswordLastChanged();
			if(	passwordLastChanged == User.PASSWORD_LAST_CHANGED_FORCE ) {
				request.getSession().setAttribute(ProfileServlet.FORCED_CHANGE_PARAMETER, "Y");
				response.sendRedirect(request.getContextPath()+FORCED_CHANGE_PASSWORD);
				return;
			}

			PasswordRestriction pwRes =
				PasswordRestrictionDAO.getInstance().getById(PasswordRestriction.LOGIN_PASSWORD_RESTRICTION_ID);
			if(pwRes != null ) {
		    	if( pwRes.getLifetime() > 0 ) {
		    		long expiryDate = DateFormatter.getDateInPast(pwRes.getLifetime());
		    		if(	expiryDate > passwordLastChanged) {
		    			request.setAttribute(ProfileServlet.FORCED_CHANGE_PARAMETER, "Y");
						request.getRequestDispatcher(FORCED_CHANGE_PASSWORD).forward(request, response);
						return;
		    		}
		    	}
			}

			// Get the list of upgrades that need to be made.
			if( userClassifier.isAdministrator(thisUser) ) {
				List<String> upgrades = getUpgradeList();
				if(upgrades != null ) {
					request.setAttribute("upgrade_list", upgrades);
					request.getRequestDispatcher("/admin/upgrades_available.jsp").forward(request, response);
					return;
				}
			}

	    	// If not check for expiring passwords.
	        if (PasswordDAO.getInstance().hasExpiringPasswords(thisUser)) {
	        	response.sendRedirect(response.encodeRedirectURL(EXPIRING_PASSWORDS_PAGE));
	            return;
	        }

	        // If there are no expiring passwords then go to the explorer page
	        response.sendRedirect(request.getContextPath()+ServletPaths.getExplorerPath());
    	} catch(Exception ex) {
    		throw new ServletException("There was a problem after you logged on.", ex);
    	}
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Servlet to direct the user to the correct page when they log in";
    }

    /**
     * Get the list of upgrades which are needed.
     *
     * @return A List of upgrades which are available.
     */

    private List<String> getUpgradeList()
    	throws SQLException {
    	List<String> returnValue = null;

    	if(!GroupDAO.getInstance().idExists(Group.ALL_USERS_GROUP_ID)) {
    		returnValue = new ArrayList<String>();
    		returnValue.add("Group containing all users");
    	}

        if(!GroupDAO.getInstance().idExists(Group.NON_VIEWING_GROUP_ID)) {
            if(returnValue == null) {
                returnValue = new ArrayList<String>();
            }
            returnValue.add("Ability to have users who can't view passwords");
        }

        return returnValue;
    }
}
