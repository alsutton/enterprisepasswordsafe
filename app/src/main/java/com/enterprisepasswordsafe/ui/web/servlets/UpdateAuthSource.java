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
import com.enterprisepasswordsafe.model.dao.AuthenticationSourceDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;

/**
 * Servlet to update an authentication source.
 */

public final class UpdateAuthSource extends AuthSourceModificationServlet {

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
        throws ServletException, IOException {
        String id = request.getParameter("id");

        String name = request.getParameter("name");
        Map<String,String> parameters = extractAuthParameters(request);

        AuthenticationSourceDAO asDAO = AuthenticationSourceDAO.getInstance();
        try {
	        AuthenticationSource source = asDAO.getById(id);
	        source.setName(name);
	        source.setProperties(parameters);
	        asDAO.update(source);
	        ServletUtils.getInstance().generateMessage(request, "The authentication source has been updated.");
	        request.getRequestDispatcher("/admin/EditAuthSource").forward(request, response);
        } catch(SQLException sqle) {
        	throw new ServletException("There was a problem updating the authentication source.", sqle);
        }
    }

    @Override
	public String getServletInfo() {
        return "Servlet to update an authentication source.";
    }
}
