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

import com.enterprisepasswordsafe.database.*;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Enumeration;


/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class StoreIMScript extends HttpServlet {

	/**
	 * The message shown when the script is store successfully.
	 */

	private static final String SUCCESSFUL_MESSAGE =
				"The script was successfully stored.";

	/**
	 * The prefix for the integration module properties.
	 */

	public static final String MODULE_CONFIG_PREFIX = "mc_";

	/**
	 * The prefix for the integration module properties.
	 */

	public static final int MODULE_CONFIG_PREFIX_LENGTH = MODULE_CONFIG_PREFIX.length();

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	try {
	    	String moduleId = (String) request.
										getSession().
	    									getAttribute(IntegrationModuleScripts.INTEGRATION_MODULE_ID);

	    	IntegrationModule theModule = IntegrationModuleDAO.getInstance().getById(moduleId);
	    	String scriptId = request.getParameter("scriptid");
	    	String name = request.getParameter("name");
	    	String script = request.getParameter("script");

	    	IntegrationModuleScriptDAO imsDAO = IntegrationModuleScriptDAO.getInstance();
	    	IntegrationModuleScript scriptDetails = imsDAO.getById(scriptId);

	    	if(scriptDetails == null) {
	    		scriptDetails = new IntegrationModuleScript(theModule.getId(),name,script);
	    		scriptId = scriptDetails.getId();
	    	} else {
	    		scriptDetails.setName(name);
	    		scriptDetails.setScript(script);
	    	}

	    	if( imsDAO.getById(scriptId) != null ) {
	    		imsDAO.update(scriptDetails);
	    	} else {
	    		imsDAO.store(scriptDetails);
	    	}

			Enumeration<String> paramNames = request.getParameterNames();
	    	while( paramNames.hasMoreElements() ) {
	    		String paramName = paramNames.nextElement();
	    		if( paramName.startsWith(MODULE_CONFIG_PREFIX) ) {
	    			IntegrationModuleConfigurationDAO.getInstance().store (
								scriptDetails,
								null,
								paramName.substring(MODULE_CONFIG_PREFIX_LENGTH),
								request.getParameter(paramName)
							);
	    		}
	    	}

	    	ServletUtils.getInstance().generateMessage(request, SUCCESSFUL_MESSAGE);
	    	request.getRequestDispatcher("/admin/IntegrationModuleScripts").forward(request, response);
    	} catch(SQLException sqle) {
    		throw new ServletException("The script could not be stored at the current time.", sqle);
    	}
    }

    @Override
	public String getServletInfo() {
        return "Store a script in the local database.";
    }
}
