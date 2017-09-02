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
import java.util.List;

import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.exceptions.DatabaseUnavailableException;
import com.enterprisepasswordsafe.ui.web.servletfilter.AuthenticationFilter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Servlet to authenticate a user logging in.
 */

public final class VerifyLogin extends LoginAuthenticationServlet {
    /**
	 *
	 */
	private static final long serialVersionUID = 8992563176702910158L;

    /**
     * The next page to send the user to.
     */

    private static final String NEXT_PAGE_REDIRECT = "/system/Welcome";

    /**
     * The next page to send the user to.
     */

    private static final String PASSWORD_SYNC_PAGE = "/passwordsync.jsp";

    /**
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	HttpSession session = request.getSession();
    	if( session != null ) {
	    	session.removeAttribute(AuthenticationFilter.USER_IS_ADMIN);
	    	session.removeAttribute(AuthenticationFilter.USER_IS_SUBADMIN);
	    	session.removeAttribute(AuthenticationFilter.ACCESS_KEY_PARAMETER);
	    	session.removeAttribute(AuthenticationFilter.USER_NAME_PARAMETER);
	    	session.removeAttribute(SecurityUtils.USER_ID_PARAMETER);
    	}

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // check the username and password were supplied
        if (username == null || password == null) {
            throw new ServletException("Please enter your username and password.");
        }

        try {
			User theUser = UserDAO.getInstance().getByName(username);
			if (theUser == null) {
				TamperproofEventLogDAO.getInstance().create(
						TamperproofEventLog.LOG_LEVEL_AUTHENTICATION,
						null,
						"An attempt was made to log in as a non-existent user ("
								+ username + ") from " + request.getRemoteHost() + ". ",
						false
				);
				ServletUtils.getInstance().generateErrorMessage(request, "There was a problem authorising your details");
				response.sendRedirect(request.getContextPath() + "/Login");
				return;
			}

			if (!theUser.isEnabled()) {
				TamperproofEventLogDAO.getInstance().create(
						TamperproofEventLog.LOG_LEVEL_AUTHENTICATION,
						theUser,
						"An attempt was made to log in as a disabled user ("
								+ username + ") from " + request.getRemoteHost() + ". ",
						false
				);
				ServletUtils.getInstance().generateErrorMessage(request, "There was a problem authorising your details");
				response.sendRedirect(request.getContextPath() + "/Login");
				return;
			}

			try {
				UserDAO.getInstance().authenticateUser(theUser, password);
			} catch (LoginException le) {
				// Handle syncing if the user enters their EPS password and it differs from the
				// auth source one.
				if (theUser.getAuthSource() != null
						&& !theUser.getAuthSource().equals(AuthenticationSource.DEFAULT_SOURCE.getSourceId())) {
					if (theUser.checkPassword(password)) {
						request.setAttribute(SecurityUtils.USER_ID_PARAMETER, theUser.getUserId());
						request.getRequestDispatcher(PASSWORD_SYNC_PAGE).forward(request, response);
						return;
					}
				}

				TamperproofEventLogDAO.getInstance().create(
						TamperproofEventLog.LOG_LEVEL_AUTHENTICATION,
						theUser,
						"An attempt to log in as the user "
								+ username + " from " + request.getRemoteHost()
								+ " failed (" + le.getLocalizedMessage() + "). ",
						false
				);
				ServletUtils.getInstance().generateErrorMessage(request, "There was a problem authorising your details");
				response.sendRedirect(request.getContextPath() + "/Login");
				return;
			}

			// Handle syncing if the user enters their Auth source password and it differs from the
			// EPS one.
			if (theUser.getAuthSource() != null
					&& !theUser.getAuthSource().equals(AuthenticationSource.DEFAULT_SOURCE.getSourceId())) {
				if (!theUser.checkPassword(password)) {
					request.setAttribute(SecurityUtils.USER_ID_PARAMETER, theUser.getUserId());
					request.getRequestDispatcher(PASSWORD_SYNC_PAGE).forward(request, response);
					return;
				}
			}

			// If the user has logged in using an external source we need to
			// ensure the external and EPS password are synchronized.
			if (!theUser.checkPassword(password)) {
				if (!theUser.getUserId().equals(User.ADMIN_USER_ID)) {
					UserDAO.getInstance().increaseFailedLogins(theUser);
				}
				ServletUtils.getInstance().generateErrorMessage(request, "Your login details are incorrect.");
				response.sendRedirect(request.getContextPath() + "/Login");
				return;
			}

			// Check for a login restriction. admin@localhost will ALWAYS be allowed.
			String address = request.getRemoteAddr();
			String userId = theUser.getUserId();
			List<UserIPZoneRestriction> restrictions = UserIPZoneRestrictionDAO.getInstance().getApplicable(userId, address);
			if (restrictions.size() > 0) {
				for (UserIPZoneRestriction thisRestriction : restrictions) {
					if (thisRestriction.getRule() == UserIPZoneRestriction.DENY_INT) {
						throw new ServletException("You can not log in from the system you are using.");
					}
				}
			} else {
				String defaultLoginAccess = ConfigurationDAO.getValue(ConfigurationOption.DEFAULT_LOGIN_ACCESS);
				if (defaultLoginAccess.equals(UserIPZoneRestriction.DENY_STRING)) {
					ServletUtils.getInstance().generateErrorMessage(request, "You can not log in from the system you are using.");
					response.sendRedirect(request.getContextPath() + "/Login");
					return;
				}
			}

			theUser.decryptAccessKey(password);
			UserDAO.getInstance().zeroFailedLogins(theUser);

			storeUserInformation(session, theUser);
			storeTimeoutInformation(session);
			String redirect = response.encodeRedirectURL(request.getContextPath() + NEXT_PAGE_REDIRECT);
			response.sendRedirect(redirect);
		} catch (DatabaseUnavailableException e) {
			response.sendRedirect(request.getContextPath()+"/VerifyJDBCConfiguration");
        } catch (SQLException sqle) {
        	throw new ServletException("An error occurred trying to log you in. ", sqle);
        } catch (GeneralSecurityException gse) {
        	throw new ServletException("An error occurred trying to log you in. ", gse);
        }
    }

    /**
     * An attempt to get bounces the user back to the main page
     */

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    	throws IOException {
    	response.sendRedirect(request.getContextPath());
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Servlet to delete a group from the system";
    }
}
