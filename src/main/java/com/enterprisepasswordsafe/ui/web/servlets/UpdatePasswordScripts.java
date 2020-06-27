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

import com.enterprisepasswordsafe.database.IntegrationModuleConfigurationDAO;
import com.enterprisepasswordsafe.database.IntegrationModuleScript;
import com.enterprisepasswordsafe.database.IntegrationModuleScriptDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.sql.SQLException;


/**
 * Servlet to alter the scripts associated with a password.
 */
public final class UpdatePasswordScripts extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = -110209754864336180L;

    /**
     * @throws UnsupportedEncodingException
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletRequest)
     */
    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	try {
	    	String passwordId = request.getParameter("id");

	    	IntegrationModuleScriptDAO imsDAO = IntegrationModuleScriptDAO.getInstance();
	    	IntegrationModuleConfigurationDAO imcDAO = IntegrationModuleConfigurationDAO.getInstance();

	    	// Run through the scripts de-activating them
			for(IntegrationModuleScript thisScript : imsDAO.getScriptsForPassword(passwordId)) {
				imcDAO.deleteProperty(
	    				thisScript,
	    				passwordId,
	    				IntegrationModuleConfigurationDAO.MODULE_CONFIGURED_PARAMETER
	    		);
	    	}


	    	String[] scriptIds = request.getParameterValues("scripts");
			for (String scriptId : scriptIds) {
				IntegrationModuleScript script = imsDAO.getById(scriptId);
				imcDAO.store(
						script,
						passwordId,
						IntegrationModuleConfigurationDAO.MODULE_CONFIGURED_PARAMETER,
						"E"
				);
			}

	        ServletUtils.getInstance().generateMessage(request, "The password configuration has been updated.");
	        request.getRequestDispatcher("/admin/AlterIntegrationScript").forward(request, response);
    	} catch(SQLException sqle) {
    		throw new ServletException("There was a problem updating the password configuration.", sqle);
    	}
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Servlet to alter the scripts associated with a password";
    }
}
