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

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;


/**
 * Servlet to send the user to the page to list the password restrictions.
 */

public final class Logout extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = 8564922764250540055L;

	/**
     * @throws IOException
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
	public void doGet(final HttpServletRequest request,
    		final HttpServletResponse response) throws IOException {
    	SecurityUtils.clearLoggedInUserDetails(request);
    	response.sendRedirect(request.getContextPath());
    }

    @Override
	public void doPost(final HttpServletRequest request,
    		final HttpServletResponse response) throws IOException {
    	doGet(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Servlet to log the user off of the system.";
    }
}
