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

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import com.enterprisepasswordsafe.engine.database.GroupDAO;
import com.enterprisepasswordsafe.engine.database.User;
import org.apache.commons.csv.CSVRecord;


public final class ImportGroups extends ImporterServlet {
	private static final long serialVersionUID = 8232251215580907740L;

    @Override
	public String getServletInfo() {
        return "Imports groups into the database.";
    }

    @Override
	public void importEntry(HttpServletRequest request, final User theUser, final String parentNode,
							CSVRecord record)
        throws ServletException {
    	try {
			((GroupDAO)request.getAttribute("groupDAO")).importGroup(theUser, record);
		} catch (UnsupportedEncodingException e) {
			throw new ServletException("Group import failed.", e);
		} catch (SQLException e) {
			throw new ServletException("Group import failed.", e);
		} catch (GeneralSecurityException e) {
			throw new ServletException("Group import failed.", e);
		}
    }

    @Override
	protected void setImportAttributes(final HttpServletRequest request) {
    	request.setAttribute("groupDAO", GroupDAO.getInstance());
    	return;		// Do nothing
    }

}
