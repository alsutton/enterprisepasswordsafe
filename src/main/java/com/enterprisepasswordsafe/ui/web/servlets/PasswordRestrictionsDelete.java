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
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.Group;
import com.enterprisepasswordsafe.engine.database.GroupDAO;
import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.engine.database.PasswordDAO;
import com.enterprisepasswordsafe.engine.database.PasswordRestrictionDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

public final class PasswordRestrictionsDelete extends HttpServlet {

    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	try {
	    	User user = SecurityUtils.getRemoteUser(request);
	    	String id = request.getParameter("id");

	    	List<Password> inUseBy = PasswordDAO.getInstance().getPasswordsRestrictionAppliesTo(id);
	    	if( !inUseBy.isEmpty() ) {
	    		request.setAttribute("block_list", inUseBy);
	    		request.getRequestDispatcher("/admin/pr_cant_delete.jsp").forward(request, response);
	    		return;
	    	}

	    	PasswordRestrictionDAO prDAO = PasswordRestrictionDAO.getInstance();
	    	prDAO.delete(id);

	    	ServletUtils.getInstance().generateMessage(request, "The restriction has been deleted.");
	    } catch(Exception ex) {
	    	request.setAttribute("error_page", "/admin/PasswordRestrictions");
	    	throw new ServletException("The password restriction could not be deleted.", ex);
	    }

    	request.getRequestDispatcher("/admin/PasswordRestrictions").forward(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Servlet to attempt to delete a password restriction.";
    }
}
