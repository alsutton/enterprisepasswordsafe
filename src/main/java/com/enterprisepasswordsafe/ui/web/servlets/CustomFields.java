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

import com.enterprisepasswordsafe.database.ConfigurationDAO;
import com.enterprisepasswordsafe.ui.web.password.CustomFieldPopulator;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;
import java.util.TreeMap;

public final class CustomFields extends HttpServlet {

    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
    	final Map<String,String> customFields = new TreeMap<>();
    	final ConfigurationDAO cDAO = ConfigurationDAO.getInstance();

    	try {
			new CustomFieldPopulator().populateRequestWithDefaultCustomFields(request);
	    } catch(SQLException sqle) {
	    	throw new ServletException("The custom fields can not be altered at this time.", sqle);
	    }
        request.getRequestDispatcher("/admin/configure_custom_fields.jsp").forward(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Servlet to allow the user to edit the default custom fields.";
    }
}
