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

import com.enterprisepasswordsafe.engine.utils.PasswordRestrictionUtils;
import com.enterprisepasswordsafe.ui.web.utils.PasswordGenerator;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;

/**
 * Generate a random password for use by the password editing page.
 */

public final class PasswordGeneratorServlet extends HttpServlet {

	/**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Generates a password, possibly using a password restriction as a template.";
    }

    /**
     * @see HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
	@Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
		throws ServletException, IOException {

        PasswordRestrictionUtils restriction = null;

        String restrictionId = request.getParameter("rid");
        if(restrictionId != null && !restrictionId.isEmpty()) {
            try {
                restriction = PasswordRestrictionDAO.getInstance().getById(restrictionId);
            } catch(SQLException e) {
                throw new ServletException(e);
            }
        }

        PasswordGenerator generator = PasswordGenerator.getInstance();
        String password;
        if(restriction == null) {
            password = generator.generate();
        } else {
            password = generator.generate(restriction);
        }

        response.getWriter().print(password);
    }
}
