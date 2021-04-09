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

package com.enterprisepasswordsafe.ui.web.rawapi;

import com.enterprisepasswordsafe.model.dao.UserDAO;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;


public abstract class RawAPIServlet extends HttpServlet {

	/**
	 * Prevent the GET method being used. If a HTTP GET is attempted the
	 * bad request error code is returned.
	 */

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response)
		throws IOException {
		response.sendError(HttpServletResponse.SC_BAD_REQUEST);
	}

	/**
	 * Get the username of the user attempting to use the service.
	 *
	 * @param request The servlet request being serviced.
	 * @return The username of the user attempting to use the server.
	 */

	protected String getUsername(HttpServletRequest request) {
		return request.getParameter("username");
	}

	/**
	 * Get the password of the user attempting to use the service.
	 *
	 * @param request The servlet request being serviced.
	 * @return The password of the user attempting to use the server.
	 */

	protected String getPassword(HttpServletRequest request) {
		return request.getParameter("password");
	}

	/**
	 * Get and authenticate the user who is trying to use the system.
	 *
	 * @param request The request being serviced.
	 * @return The User attempting to use the service.
	 */
	protected User getAndAuthenticateUser(HttpServletRequest request)
		throws IOException, SQLException, GeneralSecurityException {
		String username = getUsername(request);
        String password = getPassword(request);

        UserDAO uDAO = UserDAO.getInstance();
        User theUser = uDAO.getByName(username);
        uDAO.authenticateUser(theUser, password);
        theUser.decryptAccessKey(password);

        return theUser;
	}
}
