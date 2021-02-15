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

import com.enterprisepasswordsafe.database.AuthenticationSourceDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Map;


/**
 * Servlet to list the authentication sources.
 */

public final class AddAuthSource extends AuthSourceModificationServlet {

    /**
     * @see AuthSourceModificationServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
        String type = request.getParameter("type");
        String name = request.getParameter("name");
        Map<String,String> parameters = extractAuthParameters(request);

        try {
        	request.setAttribute("error_page", "/admin/AuthSources");
        	AuthenticationSourceDAO.getInstance().create(name, type, parameters);
        	ServletUtils.getInstance().generateMessage(request, "The source has been created.");
        } catch(SQLException | GeneralSecurityException sqle) {
        	throw new ServletException("There was a problem creating the authentication source.\n("+sqle.getMessage()+").", sqle);
        }

        response.sendRedirect(request.getContextPath()+"/admin/AuthSources");
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Servlet to add an authentication source to the list of available sources";
    }
}
