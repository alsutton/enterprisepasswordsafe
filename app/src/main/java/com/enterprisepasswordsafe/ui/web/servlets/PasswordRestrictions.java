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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;

/**
 * Servlet to send the user to the page to list the password restrictions.
 */

public final class PasswordRestrictions extends HttpServlet {
    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	try {
    		request.setAttribute("restriction_list", PasswordRestrictionDAO.getInstance().getAll());
    	} catch(SQLException sqle) {
    		throw new ServletException("The password restriction list is unavailable at the current time.", sqle);
    	}
    	request.getRequestDispatcher("/admin/passwordrestrictions.jsp").forward(request, response);

    }

    @Override
	public String getServletInfo() {
        return "Servlet to obtain the list of password restrictions and direct the user to the appropriate page.";
    }
}
