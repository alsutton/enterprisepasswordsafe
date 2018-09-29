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
import java.io.UnsupportedEncodingException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.List;

import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.exceptions.DatabaseUnavailableException;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.ui.web.servletfilter.AuthenticationFilter;
import com.enterprisepasswordsafe.ui.web.utils.ForwardException;
import com.enterprisepasswordsafe.ui.web.utils.RedirectException;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

public final class VerifyLogin extends LoginAuthenticationServlet {

    private static final String NEXT_PAGE_REDIRECT = "/system/Welcome";
    private static final String PASSWORD_SYNC_PAGE = "/passwordsync.jsp";

    private UserClassifier userClassifier = new UserClassifier();

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	HttpSession session = getClearSession(request);

        String username = request.getParameter("username");
        String password = request.getParameter("password");
        if (username == null || password == null) {
            throw new ServletException("Please enter your username and password.");
        }

        try {
            User theUser = getUser(request, username);
            authenticateUser(request, theUser, password);
			storeUserInformation(session, theUser);
			storeTimeoutInformation(session);
			String redirect = response.encodeRedirectURL(request.getContextPath() + NEXT_PAGE_REDIRECT);
			response.sendRedirect(redirect);
        } catch (RedirectException e) {
            response.sendRedirect(request.getContextPath() + e.getDestination());
        } catch (ForwardException e) {
            request.getRequestDispatcher(e.getDestination()).forward(request, response);
		} catch (DatabaseUnavailableException e) {
			response.sendRedirect(request.getContextPath()+"/VerifyJDBCConfiguration");
        } catch (SQLException | GeneralSecurityException e) {
        	throw new ServletException("An error occurred trying to log you in. ", e);
        }
    }

    private HttpSession getClearSession(HttpServletRequest request) {
        HttpSession session = request.getSession();
        if( session != null ) {
            session.removeAttribute(AuthenticationFilter.USER_IS_ADMIN);
            session.removeAttribute(AuthenticationFilter.USER_IS_SUBADMIN);
            session.removeAttribute(AuthenticationFilter.ACCESS_KEY_PARAMETER);
            session.removeAttribute(AuthenticationFilter.USER_NAME_PARAMETER);
            session.removeAttribute(SecurityUtils.USER_ID_PARAMETER);
        }
        return session;
	}

	private User getUser(HttpServletRequest request, final String username)
            throws RedirectException, SQLException, UnsupportedEncodingException, GeneralSecurityException {
        User theUser = UserDAO.getInstance().getByName(username);
        if (theUser == null) {
            TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_AUTHENTICATION,
                    null, "An attempt was made to log in as a non-existent user ("
                            + username + ") from " + request.getRemoteHost() + ". ",false);
            ServletUtils.getInstance().generateErrorMessage(request, "There was a problem authorising your details");
            throw new RedirectException("/Login");
        }

        if (!theUser.isEnabled()) {
            TamperproofEventLogDAO.getInstance().create(
                    TamperproofEventLog.LOG_LEVEL_AUTHENTICATION,
                    theUser, "An attempt was made to log in as a disabled user ("
                            + username + ") from " + request.getRemoteHost() + ". ", false);
            ServletUtils.getInstance().generateErrorMessage(request, "There was a problem authorising your details");
            throw new RedirectException("/Login");
        }
        return theUser;
    }

    private void authenticateUser(HttpServletRequest request, User user, String password)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException,
            RedirectException, ForwardException, ServletException, UnknownHostException {
        try {
            UserDAO.getInstance().authenticateUser(user, password);
        } catch (LoginException e) {
            handleAuthenticationFailure(request, user, password, e.getLocalizedMessage());
        }
        checkRemoteAndLocalPasswordsMatch(request, user, password);
        if (!user.checkPassword(password)) {
            handleFailedLogin(request, user);
        }
        checkLoginRestrictions(request, user);
        user.decryptAccessKey(password);
        UserDAO.getInstance().zeroFailedLogins(user);
    }

    private void handleAuthenticationFailure(HttpServletRequest request, User user, String password,
                                             String failureMessage)
            throws ForwardException, RedirectException, UnsupportedEncodingException,
            GeneralSecurityException, SQLException {
        if (user.getAuthSource() != null
                && !user.getAuthSource().equals(AuthenticationSource.DEFAULT_SOURCE.getSourceId())) {
            if (user.checkPassword(password)) {
                request.setAttribute(SecurityUtils.USER_ID_PARAMETER, user.getId());
                throw new ForwardException(PASSWORD_SYNC_PAGE);
            }
        }

        TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_AUTHENTICATION,
                user, "An attempt to log in as the user " + user.getUserName() + " from " +
                        request.getRemoteHost() + " failed (" + failureMessage + "). ", false);
        ServletUtils.getInstance().generateErrorMessage(request, "There was a problem authorising your details");
        throw new RedirectException("/Login");
    }

    private void checkRemoteAndLocalPasswordsMatch(HttpServletRequest request, User user, String password)
            throws ForwardException, UnsupportedEncodingException, NoSuchAlgorithmException {
        if (user.getAuthSource() == null
        ||  user.getAuthSource().equals(AuthenticationSource.DEFAULT_SOURCE.getSourceId())) {
            return;
        }

        if (user.checkPassword(password)) {
            return;
        }

        request.setAttribute(SecurityUtils.USER_ID_PARAMETER, user.getId());
        throw new ForwardException(PASSWORD_SYNC_PAGE);
    }

    private void handleFailedLogin(HttpServletRequest request, User user)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException, RedirectException {
        if (!userClassifier.isMasterAdmin(user)) {
            UserDAO.getInstance().increaseFailedLogins(user);
        }
        ServletUtils.getInstance().generateErrorMessage(request, "Your login details are incorrect.");
        throw new RedirectException("/Login");
    }

    private void checkLoginRestrictions(HttpServletRequest request, User user)
            throws GeneralSecurityException, SQLException, UnknownHostException, ServletException, RedirectException {
        String address = request.getRemoteAddr();
        String userId = user.getId();
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
                throw new RedirectException("/Login");
            }
        }
    }

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    	throws IOException {
    	response.sendRedirect(request.getContextPath());
    }

    @Override
	public String getServletInfo() {
        return "Servlet to delete a group from the system";
    }
}
