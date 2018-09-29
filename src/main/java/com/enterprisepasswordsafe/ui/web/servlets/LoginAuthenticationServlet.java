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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.SQLException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpSession;

import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.ui.web.servletfilter.AuthenticationFilter;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import org.apache.commons.codec.binary.Base64;

public abstract class LoginAuthenticationServlet extends HttpServlet {

	public static final String USER_OBJECT_SESSION_ATTRIBUTE = "UserObject";

	private UserClassifier userClassifier = new UserClassifier();

    final void storeUserInformation(final HttpSession session, final User theUser)
        throws SQLException, NoSuchAlgorithmException {
        if (userClassifier.isAdministrator(theUser)) {
            session.setAttribute(AuthenticationFilter.USER_TYPE_PARAMETER, AuthenticationFilter.FULL_ADMIN);
            session.setAttribute(AuthenticationFilter.USER_IS_ADMIN, "X");
            session.setAttribute(AuthenticationFilter.USER_IS_SUBADMIN, "X");
        } else if (userClassifier.isSubadministrator(theUser)) {
            session.setAttribute(AuthenticationFilter.USER_TYPE_PARAMETER, AuthenticationFilter.SUB_ADMIN);
            session.removeAttribute(AuthenticationFilter.USER_IS_ADMIN);
            session.setAttribute(AuthenticationFilter.USER_IS_SUBADMIN, "X");
        } else {
            session.setAttribute(AuthenticationFilter.USER_TYPE_PARAMETER, AuthenticationFilter.NORMAL_USER);
            session.removeAttribute(AuthenticationFilter.USER_IS_ADMIN);
            session.removeAttribute(AuthenticationFilter.USER_IS_SUBADMIN);
        }
        session.setAttribute(AuthenticationFilter.ACCESS_KEY_PARAMETER, theUser.getAccessKey());

        String name = theUser.getFullName();
        if (name == null) {
            name = theUser.getUserName();
        }
        session.setAttribute(AuthenticationFilter.USER_NAME_PARAMETER, name );
        session.setAttribute(SecurityUtils.USER_ID_PARAMETER, theUser.getId());
        session.setAttribute(USER_OBJECT_SESSION_ATTRIBUTE, theUser);

        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[32];
        sr.nextBytes(random);
        session.setAttribute("csrfToken", new Base64(0, null, true).encodeAsString(random));
    }

    final void storeTimeoutInformation(final HttpSession session)
            throws SQLException {
        // Set the session invalidation timeout period
        String sessionTimeout = ConfigurationDAO.getValue(ConfigurationOption.SESSION_TIMEOUT);
        if ("0".equals(sessionTimeout)) {
        	sessionTimeout = Integer.toString(Integer.MAX_VALUE);
        }

        int sessionTimeoutInt;
        try {
            sessionTimeoutInt = Integer.parseInt(sessionTimeout);
        } catch (NumberFormatException ex) {
            sessionTimeoutInt = Integer.parseInt(ConfigurationOption.SESSION_TIMEOUT.getDefaultValue());
        }
        session.setMaxInactiveInterval(sessionTimeoutInt * DateFormatter.SECONDS_IN_MINUTE);
    }

}
