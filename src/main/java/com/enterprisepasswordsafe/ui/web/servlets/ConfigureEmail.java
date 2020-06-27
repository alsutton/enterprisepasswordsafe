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
import com.enterprisepasswordsafe.ui.web.utils.JSTLParameterNameSanitiser;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public final class ConfigureEmail extends HttpServlet {

    private static final String[] PARAMETER_NAMES = {
            "smtp.enabled.authentication",
            "smtp.enabled.configuration",
            "smtp.enabled.reports",
            "smtp.enabled.user_manipulation",
            "smtp.enabled.group_manipulation",
            "smtp.enabled.object_manipulation",
            "smtp.enabled.hierarchy_manipulation",
            ConfigurationOption.SMTP_TO_PROPERTY.getPropertyName(),
            ConfigurationOption.INCLUDE_USER_ON_AUDIT_EMAIL.getPropertyName() };

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        try {
            ConfigurationDAO cDAO = ConfigurationDAO.getInstance();
            for (String parameterName : PARAMETER_NAMES) {
                transferSettingToRequest(request, cDAO, parameterName);
            }

            request.getRequestDispatcher("/admin/setup_email_events.jsp").forward(request, response);
        } catch(SQLException e) {
            throwServletException(e);
        }
    }

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
    	throws ServletException {
    	try {
	        User thisUser = SecurityUtils.getRemoteUser(request);

	        ConfigurationDAO cDAO = ConfigurationDAO.getInstance();
	        TamperproofEventLogDAO telDAO = TamperproofEventLogDAO.getInstance();
            for(String parameterName : PARAMETER_NAMES) {
	            transferSettingToDatabase(request, cDAO, telDAO, thisUser, parameterName);
	        }

	        ServletUtils.getInstance().generateMessage(request, "The settings have been updated.");

            response.sendRedirect(request.getContextPath()+"/admin/ConfigureEmail");
    	} catch(Exception ex) {
            throwServletException(ex);
    	}
    }

    private void throwServletException(final Exception e)
        throws ServletException {
        throw new ServletException("The Email settings could not be retrieved due to an error.", e);
    }

    private void transferSettingToRequest(final HttpServletRequest request,
                                          final ConfigurationDAO cDAO, final String parameterName)
            throws SQLException {
        request.setAttribute(
                JSTLParameterNameSanitiser.santiseName(parameterName),
                cDAO.get(parameterName, null)
        );
    }

    private void transferSettingToDatabase(final HttpServletRequest request,
    		final ConfigurationDAO cDAO, TamperproofEventLogDAO telDAO,
    		final User thisUser,  final String parameterName) throws SQLException,
            GeneralSecurityException, UnsupportedEncodingException {
        String value = request.getParameter(parameterName);
        String originalValue = cDAO.get(parameterName, null);

        if (value != null && value.isEmpty()) {
            value = null;
        }

        if ((value == null && originalValue != null)
         || (value != null && !value.equals(originalValue))) {
            String printValue = value;
            if (value == null) {
                printValue = "";
            }

            String message =  "Changed the event email setting "
                            +  parameterName
                            + " to be \""
                            + printValue
                            + '\"';

            telDAO.create( TamperproofEventLog.LOG_LEVEL_CONFIGURATION, thisUser, null, message, true );
        }

        cDAO.set(parameterName, value);
    }
}
