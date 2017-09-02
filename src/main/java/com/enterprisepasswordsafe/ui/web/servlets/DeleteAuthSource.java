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
import java.sql.SQLException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.AuthenticationSource;
import com.enterprisepasswordsafe.engine.database.AuthenticationSourceDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

public final class DeleteAuthSource extends HttpServlet {

    private static final String NEXT_PAGE = "/admin/AuthSources";

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
    	request.setAttribute("error_page", NEXT_PAGE);

        String id = request.getParameter("id");
        try {
	        AuthenticationSource source = AuthenticationSourceDAO.getInstance().getById(id);
	        if( source == null ) {
	        	throw new ServletException("The specified authentication source was not found.");
	        }

	        String defaultSource = ConfigurationDAO.getValue(ConfigurationOption.DEFAULT_AUTHENTICATION_SOURCE_ID);
	        if( defaultSource != null && defaultSource.equals(id)) {
	        	throw new ServletException("The source can not be deleted because it is currently the default source.");
	        }

	        deleteIfUnused(request, source);
        } catch( SQLException e ) {
        	throw new ServletException("There was a problem deleting the authentication source.", e);
        }
        response.sendRedirect(request.getContextPath() + NEXT_PAGE);
    }

	private void deleteIfUnused(HttpServletRequest request,  AuthenticationSource source)
		throws SQLException {
		AuthenticationSourceDAO asDAO = AuthenticationSourceDAO.getInstance();
		List<String> users = asDAO.getUsernames(source);
		if( users == null || users.isEmpty() ) {
			delete(request, asDAO, source);
		} else {
			generateErrorForSourceInUse(request, users);
		}
	}

	private void delete(final HttpServletRequest request, final AuthenticationSourceDAO authenticationSourceDAO,
						final AuthenticationSource source)
		throws SQLException {
		authenticationSourceDAO.delete(source);
		ServletUtils.getInstance().generateMessage(request, "The authentication source has been deleted");
	}

	private void generateErrorForSourceInUse(final HttpServletRequest request, final List<String> users) {
		StringBuilder message =
				new StringBuilder("The source could not be deleted because it is still in use by the following users ;");
		for(String thisUser : users) {
			message.append(' ');
			message.append(thisUser);
			message.append(',');
		}
		message.deleteCharAt(message.length()-1);
		ServletUtils.getInstance().generateErrorMessage(request, message.toString());
	}
}
