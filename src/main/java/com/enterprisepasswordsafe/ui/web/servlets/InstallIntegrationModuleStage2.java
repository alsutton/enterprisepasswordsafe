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
import com.enterprisepasswordsafe.database.IntegrationModuleDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class InstallIntegrationModuleStage2 extends HttpServlet {

    @Override
	protected void doPost( final HttpServletRequest request, final HttpServletResponse response )
            throws ServletException, IOException {

    	request.setAttribute("error_page", "/admin/im_install_stage1.jsp");

    	String className = request.getParameter("im.name");
    	if( className == null || className.length() == 0 ) {
    		throw new ServletException("An integration module name was not specified.");
    	}

    	Class<?> theClass;
    	try {
    		theClass = Class.forName(className);
    	} catch( ClassNotFoundException cnfe ) {
    		try {
    			theClass = Class.forName("com.enterprisepasswordsafe.passwordsafe.integration.integrators."+className);
    		} catch( ClassNotFoundException cnf ) {
    			throw new ServletException("The integration module is unavailable at the current time.", cnfe);
    		}
    	}

    	try {
        	IntegrationModuleDAO.getInstance().install(new IntegrationModule(className, theClass.getName()));
    	} catch(Exception ex) {
    		throw new ServletException("The integration module is unavailable at the current time.", ex);
    	}

    	ServletUtils.getInstance().generateMessage(request, "The module has been installed.");
    	request.getRequestDispatcher("/admin/IntegrationModules").forward(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Installs a specified integration module and forwards the user to the configuration page.";
    }
}
