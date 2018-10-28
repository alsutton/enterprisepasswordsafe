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
import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Servlet to configure the JDBC connection information.
 */

public class SetJDBCConfiguration extends HttpServlet {

    @Override
	public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
    	request.setAttribute("error_page", "/");

    	try {
            JDBCConnectionInformation jdbcConfig = Repositories.jdbcConfigurationRepository.load();
            jdbcConfig.dbType = request.getParameter("database");
            jdbcConfig.driver = request.getParameter("jdbcdriver");
            jdbcConfig.url = request.getParameter("jdbcurl");
            jdbcConfig.username = request.getParameter("jdbcusername");
            jdbcConfig.password = request.getParameter("jdbcpassword");
            Repositories.jdbcConfigurationRepository.store(jdbcConfig);

            // Initialise the database if so requested.
            final String initialise = request.getParameter("initialise");
            if (initialise != null && initialise.trim().equalsIgnoreCase("Yes")) {
                Logger.getLogger(getClass().toString()).log(Level.WARNING,"Initialising Database");
                DatabasePool pool = Repositories.databasePoolFactory.getInstance();
                pool.initialiseDatabase();
            }
        } catch (Exception e) {
        	Logger.getAnonymousLogger().log(Level.SEVERE, "Error setting JDBC configuration", e);
        	throw new ServletException("An error occurred whilst configuring your database.", e);
        }

        ServletUtils.getInstance().generateMessage(request, "The database configuration has been updated");
        response.sendRedirect(request.getContextPath()+"/Logout");
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Servlet to set the JDBC connection information";
    }

}
