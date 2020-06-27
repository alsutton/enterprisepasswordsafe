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

import com.enterprisepasswordsafe.database.IntegrationModuleScriptDAO;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class IntegrationModuleScripts extends HttpServlet {

	/**
	 *
	 */
	private static final long serialVersionUID = 3241549479926431269L;

	/**
	 * The parameter name for the integration module name.
	 */

	public static final String INTEGRATION_MODULE_ID = "imid";

	/**
	 * The parameter name for the list of scripts
	 */

	public static final String IM_SCRIPT_LIST = "scripts";

	/**
	 * The parameter name for the list of scripts
	 */

	public static final String IM_MODULE = "module";

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletResponse)
     */
    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    	throws ServletException, IOException {
    	try {
	    	String moduleId = request.getParameter(INTEGRATION_MODULE_ID);
	    	if( moduleId == null || moduleId.length() == 0 ) {
	    		moduleId =(String) request.getSession().getAttribute(INTEGRATION_MODULE_ID);
	    	}

	        request.getSession().setAttribute(INTEGRATION_MODULE_ID, moduleId);
	    	request.setAttribute(IM_SCRIPT_LIST,
	    			IntegrationModuleScriptDAO.getInstance().getAll(moduleId));
	    	request.setAttribute( "moduleId", moduleId );
    	} catch(Exception sqle) {
    		request.setAttribute("error_page", "/admin/IntegrationModules");
    		throw new ServletException("The list of scripts are unavailable at the current time.", sqle);
    	}
    	request.getRequestDispatcher("/admin/im_scripts.jsp").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Installs a specified integration module and forwards the user to the configuration page.";
    }
}
