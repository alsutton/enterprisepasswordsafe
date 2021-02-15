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

import com.enterprisepasswordsafe.database.AuthenticationSource;
import com.enterprisepasswordsafe.database.AuthenticationSourceDAO;
import com.enterprisepasswordsafe.database.ConfigurationDAO;
import com.enterprisepasswordsafe.database.ConfigurationOption;
import com.enterprisepasswordsafe.ui.web.utils.JSTLParameterNameSanitiser;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;
import com.enterprisepasswordsafe.ui.web.utils.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;


public final class Configure extends HttpServlet {

    private static final ConfigurationOption[] OPTIONS = {
        ConfigurationOption.SMTP_HOST,
        ConfigurationOption.SMTP_FROM,
        ConfigurationOption.LOGIN_ATTEMPTS,
        ConfigurationOption.DEFAULT_LOGIN_ACCESS,
        ConfigurationOption.SESSION_TIMEOUT,
        ConfigurationOption.PASSWORD_ON_SCREEN_TIME,
        ConfigurationOption.PROPERTY_SERVER_BASE_URL,
        ConfigurationOption.REJECT_HISTORICAL_EXPIRY_DATES,
        ConfigurationOption.DEFAULT_HIERARCHY_ACCESS_RULE,
        ConfigurationOption.HIDE_EMPTY_FOLDERS,
        ConfigurationOption.STORE_PASSWORD_HISTORY,
        ConfigurationOption.PASSWORD_AUDIT_LEVEL,
        ConfigurationOption.REPORT_SEPARATOR,
        ConfigurationOption.HIDDEN_PASSWORD_ENTRY,
        ConfigurationOption.ALLOW_BACK_BUTTON_TO_ACCESS_PASSWORD,
        ConfigurationOption.PASSWORD_DISPLAY_TYPE,
        ConfigurationOption.PASSWORD_DISPLAY,
        ConfigurationOption.PASSWORD_REASON_FOR_VIEWING_REQUIRED,
        ConfigurationOption.PASSWORD_HIDE_SYSTEM_SELECTOR,
        ConfigurationOption.RAR_LIFETIME,
        ConfigurationOption.MAX_FUTURE_EXPIRY_DISTANCE,
        ConfigurationOption.PERMISSION_PRECEDENCE,
        ConfigurationOption.DEFAULT_AUTHENTICATION_SOURCE_ID,
        ConfigurationOption.SUBADMINS_HAVE_HISTORY_ACCESS,
        ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL,
        ConfigurationOption.VOTE_ON_OWN_RA_REQUESTS,
	};

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        try {
            ConfigurationDAO cDAO = ConfigurationDAO.getInstance();

            for(ConfigurationOption option : OPTIONS) {
                setRequestAttributeFromConfiguration(request, cDAO, option);
            }

            setAuthenticationSourceRequestAttributes(request);

            request.getRequestDispatcher("/admin/configure.jsp").forward(request, response);
        } catch(SQLException sqle) {
            throw new ServletException("The settings could not be retreived due to an error.", sqle);
        }
    }

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
        throws ServletException, IOException {
        if(!hasValidNumericParameters(request, response)) {
            return;
        }

        try {
	        ConfigurationDAO cDAO = ConfigurationDAO.getInstance();
            for(ConfigurationOption option : OPTIONS) {
	        	setConfigurationFromRequestParameter(request, cDAO, option);
	        }

	        ServletUtils.getInstance().generateMessage(request, "The settings have been updated.");
    	} catch(SQLException sqle) {
    		throw new ServletException("The settings could not be updated due to an error.", sqle);
    	}

        response.sendRedirect(request.getContextPath()+"/admin/Configure");
    }

    private void setAuthenticationSourceRequestAttributes(final HttpServletRequest request)
        throws SQLException {
        String sourceId = (String) request.getAttribute("user.default_auth_source");

        final AuthenticationSourceDAO asDAO = AuthenticationSourceDAO.getInstance();
        AuthenticationSource source = asDAO.getById(sourceId);
        if( source == null ) {
            request.setAttribute("user_defaultAuthSource", "0");
        } else {
            request.setAttribute("user_defaultAuthSourceName", source.getName());
        }
        request.setAttribute("auth_list", asDAO.getAll());

    }

    private boolean hasValidNumericParameters(final HttpServletRequest request, final HttpServletResponse response)
        throws IOException {
        String timeOut = request.getParameter(ConfigurationOption.SESSION_TIMEOUT.getPropertyName());
        if(!StringUtils.isNumber(timeOut)) {
            handleError(request, response, "The session timeout value must be an integer.");
            return false;
        }

        String onScreenTime = request.getParameter(ConfigurationOption.PASSWORD_ON_SCREEN_TIME.getPropertyName());
        if(!StringUtils.isNumber(onScreenTime)) {
            handleError(request, response, "The &quot;password on screen&quot; time must be an integer.");
            return false;
        }

        return true;
    }

    private void handleError(final HttpServletRequest request, final HttpServletResponse response, final String error)
        throws IOException {
        ServletUtils.getInstance().generateErrorMessage(request, error);
        response.sendRedirect(request.getContextPath()+"/admin/Configure");
    }

    private void setRequestAttributeFromConfiguration(final HttpServletRequest request, final ConfigurationDAO cDAO,
                                                      ConfigurationOption option)
            throws SQLException {
        final String value = cDAO.get(option);
        final String paramName = JSTLParameterNameSanitiser.santiseName(option.getPropertyName());
        request.setAttribute(paramName, value);
    }

    private void setConfigurationFromRequestParameter(final HttpServletRequest request,
                                                      final ConfigurationDAO cDAO,
                                                      final ConfigurationOption option)
        throws SQLException {
        String name = option.getPropertyName();
        String value = request.getParameter(name);
        if (value != null) {
        	cDAO.set(option, value);
        }
    }
}
