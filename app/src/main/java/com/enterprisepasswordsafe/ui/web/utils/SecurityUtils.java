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

package com.enterprisepasswordsafe.ui.web.utils;

import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.ui.web.servletfilter.AuthenticationFilter;
import com.enterprisepasswordsafe.ui.web.servlets.LoginAuthenticationServlet;
import com.enterprisepasswordsafe.ui.web.servlets.authorisation.AccessApprover;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public final class SecurityUtils {
    /**
     * Parameter/Attribute name used to store a user ID.
     */

    public static final String USER_ID_PARAMETER = "userId";

    /**
     * Authenticate access to this servlet.
     */

    public static void isAllowedAccess(final AccessApprover approver, final User theUser)
    	throws SQLException, GeneralSecurityException
    {
    	if(!approver.isAuthorised(theUser)) {
    		throw new GeneralSecurityException("You are not authorised to perform the requested action.");
    	}
    }


    /**
     * Gets the User object representing the current user.
     *
     * @param request The request being serviced.
     *
     * @return The User object for the remote user.
     */


    public static User getRemoteUser(HttpServletRequest request)
    	throws ServletException {
    	HttpSession session = request.getSession(false);
    	User theUser = (User) session.getAttribute(LoginAuthenticationServlet.USER_OBJECT_SESSION_ATTRIBUTE);
    	if(theUser == null) {
    		throw new ServletException("Please log in again to continue using the EPS");
    	}
    	return theUser;
    }

    /**
     * Gets the User ID related to a request
     *
     * @param request
     *            The servlet request.
     * @return The user ID from the request, or null if one was supplied.
     */

    public static String getUserId(HttpServletRequest request) {
        return ServletUtils.getInstance().getParameterValue(request, USER_ID_PARAMETER);
    }

    /**
     * Clears the details of the currently logged in user
     */

    public static void clearLoggedInUserDetails(final HttpServletRequest request) {
    	HttpSession session = request.getSession();
    	if( session != null ) {
    		session.removeAttribute(AuthenticationFilter.USER_IS_ADMIN);
    		session.removeAttribute(AuthenticationFilter.USER_IS_SUBADMIN);
            session.removeAttribute(AuthenticationFilter.ACCESS_KEY_PARAMETER);
            session.removeAttribute(AuthenticationFilter.USER_NAME_PARAMETER);
            session.removeAttribute(SecurityUtils.USER_ID_PARAMETER);
    		session.invalidate();
    	}
    }

}
