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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SetupJDBCConfiguration extends HttpServlet {

    @Override
	public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        JDBCConnectionInformation connectionInformation = Repositories.jdbcConfigurationRepository.get();
        request.setAttribute(VerifyJDBCConfiguration.JDBC_CONFIG_PROPERTY, connectionInformation);
        request.getRequestDispatcher("/admin/configure_jdbc.jsp").forward(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Servlet to set the JDBC connection information";
    }

}
