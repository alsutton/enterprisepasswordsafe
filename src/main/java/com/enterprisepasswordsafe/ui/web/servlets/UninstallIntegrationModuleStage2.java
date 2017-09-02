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

import com.enterprisepasswordsafe.engine.database.IntegrationModule;
import com.enterprisepasswordsafe.engine.database.IntegrationModuleDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class UninstallIntegrationModuleStage2 extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = 3047049034382086351L;

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletResponse)
     */
    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException {
    	String moduleId = request.getParameter("modid");

    	try {
	    	IntegrationModuleDAO imDAO = IntegrationModuleDAO.getInstance();
	    	IntegrationModule module = imDAO.getById(moduleId);
	    	imDAO.uninstall(module);

	        ServletUtils.getInstance().generateMessage(request, "The module has been removed.");
	    	request.getRequestDispatcher("/admin/IntegrationModules").forward(request, response);
    	} catch(Exception ex) {
    		throw new ServletException("The integration module can not be uninstalled at this time.");
    	}
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Uninstalls an integration module.";
    }
}
