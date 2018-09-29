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
import java.security.GeneralSecurityException;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.database.UserDAO;
import com.enterprisepasswordsafe.engine.database.derived.UserSummary;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

/**
 * Servlet to create a new user.
 */

public final class CreateNewUser extends HttpServlet {

	/**
     * @see HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
		request.setAttribute("error_page", "/admin/CreateUser");

		try {
	    	UserDAO uDAO = UserDAO.getInstance();

	        String username = request.getParameter("username");
	        if( uDAO.getByName(username) != null ) {
	        	throw new ServletException(
	        			"The username specified (" +
	        			username +
	        			") has already been used. Please use a different username.");
	        }
	        String fullname = request.getParameter("fn");
	        String email = request.getParameter("em");
	        String password1 = request.getParameter("password_1");
	        String password2 = request.getParameter("password_2");

	        String errorMessage = null;
	        if (username == null || username.length() == 0) {
	            errorMessage = "A username was not specified.";
	        } else if (fullname == null || fullname.length() == 0) {
	            errorMessage = "The users full name was not specified.";
	        } else if (email == null) {
	            email = "";
	        } else if (password1 == null || password2 == null
	                || !password1.equals(password2)) {
	            errorMessage = "The passwords you typed did not match.";
	        }

	        if (errorMessage != null) {
	            ServletUtils.getInstance().generateErrorMessage(request, errorMessage);
	            request.getRequestDispatcher("/admin/CreateUser").forward(request, response);
	            return;
	        }

	        User thisUser = SecurityUtils.getRemoteUser(request);
	        User newUser = uDAO.createUser(thisUser, new UserSummary(username, fullname), password1, email);

	        ServletUtils.getInstance().generateMessage(request, "The user was successfully created.");
			response.sendRedirect(request.getContextPath()+"/admin/User?userId="+newUser.getId());
    	} catch(SQLException sqle) {
    		throw new ServletException("The user could not be added due to an error.", sqle);
    	} catch(GeneralSecurityException sqle) {
    		throw new ServletException("The user could not be added due to an error.", sqle);
    	}

    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Creates a new user";
    }
}
