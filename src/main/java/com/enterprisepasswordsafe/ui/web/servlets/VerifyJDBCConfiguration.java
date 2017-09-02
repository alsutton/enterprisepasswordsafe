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
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.BackingStoreException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.configuration.JDBCConfiguration;
import com.enterprisepasswordsafe.engine.database.schema.SchemaVersion;
import com.enterprisepasswordsafe.engine.dbabstraction.SupportedDatabase;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

/**
 * Servlet to verify the JDBC connection information is valid.
 */

public class VerifyJDBCConfiguration extends HttpServlet {

    public static final String JDBC_CONFIG_PROPERTY = "jdbcConfig";

    private static final String CONFIGURATION_PAGE = "/configure_jdbc.jsp";

    private static final String LOGIN_PAGE = "/Login";

    private static JDBCConfiguration verifiedConfiguration = null;

    @Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        JDBCConfiguration jdbcConfig = JDBCConfiguration.getConfiguration();

        if (verifiedConfiguration != null && verifiedConfiguration.equals(jdbcConfig)) {
            response.sendRedirect(request.getContextPath() + LOGIN_PAGE);
            return;
        }

        try {
            String type = jdbcConfig.getDBType();
            if( type == null || type.length() == 0 ) {
                setJdbcConnectionInformationToDefaults();
                initialiseDatabase();
                doGet(request, response);
                return;
            }

            if ( jdbcConfig.isValid() ) {
                verifiedConfiguration = jdbcConfig;
                DatabasePoolFactory.setConfiguration(jdbcConfig);
                updateSchema();
                response.sendRedirect(request.getContextPath() + LOGIN_PAGE);
                return;
            }

	    } catch (Exception e) {
        	Logger.getAnonymousLogger().log(Level.SEVERE, "Error setting JDBC configuration", e);
            ServletUtils.getInstance().generateErrorMessage( request,
                    "An error occurred whilst configuring your database.\n("+e.toString()+")");
        }

        request.setAttribute(JDBC_CONFIG_PROPERTY, jdbcConfig);
        request.setAttribute("verifyOK", "X");
        request.setAttribute("dbTypes", JDBCConfiguration.DATABASE_TYPES);
		request.getRequestDispatcher(CONFIGURATION_PAGE).forward(request, response);
    }

    @Override
	protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }

    private void setJdbcConnectionInformationToDefaults()
            throws ClassNotFoundException, GeneralSecurityException, BackingStoreException, SQLException {
        JDBCConfiguration jdbcConfiguration = new JDBCConfiguration();

        jdbcConfiguration.setDatabaseType(SupportedDatabase.APACHE_DERBY.getType());
        jdbcConfiguration.setDriver("org.apache.derby.jdbc.EmbeddedDriver");

        String userHome = System.getProperty("user.home");
        if( userHome == null ) {
            userHome = "eps-db";
        }
        jdbcConfiguration.setURL("jdbc:derby:/" + userHome + "/pwsafe-hsqldb");

        jdbcConfiguration.setUsername("");
        jdbcConfiguration.setPassword("");

        jdbcConfiguration.store();
    }

    private void initialiseDatabase()
            throws UnsupportedEncodingException, GeneralSecurityException, InstantiationException, IllegalAccessException {
        try(DatabasePool pool = DatabasePoolFactory.getInstance()) {
            pool.initialiseDatabase();
        } catch(SQLException | ClassNotFoundException e) {
            Logger.getAnonymousLogger().log(Level.WARNING, "Error creating default database", e);
        }
    }

    private void updateSchema() {
        try {
            SchemaVersion schema = new SchemaVersion();
            if(!schema.isSchemaCurrent()) {
                schema.update();
            }
        } catch(Exception e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Exception adding features", e);
        }
    }
}
