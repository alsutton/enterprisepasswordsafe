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

import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.configuration.JDBCConnectionInformation;
import com.enterprisepasswordsafe.engine.configuration.PropertyBackedJDBCConfigurationRepository;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class VerifyJDBCConfiguration extends HttpServlet {

    public static final String JDBC_CONFIG_PROPERTY = "jdbcConfig";

    private static final String CONFIGURATION_PAGE = "/configure_jdbc.jsp";

    private static final String LOGIN_PAGE = "/Login";

    private static JDBCConnectionInformation verifiedConfiguration = null;

    @Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            JDBCConnectionInformation jdbcConfig = Repositories.jdbcConfigurationRepository.load();
            if( request.getParameter("force") != null) {
                verifiedConfiguration = null;
            } else if (isExistingConnectionInformationValid(jdbcConfig)) {
                response.sendRedirect(request.getContextPath() + LOGIN_PAGE);
                return;
            }

            request.setAttribute(JDBC_CONFIG_PROPERTY, jdbcConfig);
	    } catch (Exception e) {
        	Logger.getAnonymousLogger().log(Level.SEVERE, "Error setting JDBC configuration", e);
            ServletUtils.getInstance().generateErrorMessage( request,
                    "An error occurred whilst configuring your database.\n("+e.toString()+")");
        }
        request.setAttribute("verifyOK", "X");
        request.setAttribute("dbTypes", PropertyBackedJDBCConfigurationRepository.DATABASE_TYPES);
		request.getRequestDispatcher(CONFIGURATION_PAGE).forward(request, response);
    }

    @Override
	protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }

    private boolean isExistingConnectionInformationValid(JDBCConnectionInformation connectionInformation)
            throws SQLException, ClassNotFoundException {
        if (connectionInformation == null || ! connectionInformation.isValid()) {
            return false;
        }

        if (connectionInformation.equals(verifiedConfiguration)) {
            return true;
        }

        if (!connectionInformation.isValid()) {
            return false;
        }

        verifiedConfiguration = connectionInformation;
        Repositories.databasePoolFactory.setConfiguration(connectionInformation);
        return Repositories.databasePoolFactory.isConfigured();
    }
}
