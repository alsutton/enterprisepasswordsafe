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

import com.enterprisepasswordsafe.database.IntegrationModule;
import com.enterprisepasswordsafe.model.dao.IntegrationModuleDAO;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class UninstallIntegrationModule extends HttpServlet {

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException {
    	try {
	    	String moduleId = request.getParameter("modid");

	    	IntegrationModuleDAO imDAO = IntegrationModuleDAO.getInstance();
	    	IntegrationModule module = imDAO.getById(moduleId);

	    	if( !imDAO.isInUse(module) ) {
	        	request.getRequestDispatcher("/admin/UninstallIntegrationModuleStage2").forward(request, response);
	    	} else {
	    		request.getRequestDispatcher("/admin/im_confirm_delete.jsp").forward(request, response);
	    	}
    	} catch(Exception ex) {
    		throw new ServletException("The integration module can not be uninstalled at this time.", ex);
    	}
    }

    @Override
	public String getServletInfo() {
        return "Checks to see if a module is in use, if it isn't then uninstall it.";
    }
}
