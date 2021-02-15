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

import com.enterprisepasswordsafe.database.IntegrationModuleScript;
import com.enterprisepasswordsafe.database.IntegrationModuleScriptDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;


/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class DeleteIMScriptStage2 extends HttpServlet {

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	String scriptId = request.getParameter("scriptid");

    	try {
	    	IntegrationModuleScriptDAO imsDAO = IntegrationModuleScriptDAO.getInstance();
	    	IntegrationModuleScript scriptDetails = imsDAO.getById(scriptId);
	    	imsDAO.delete(scriptDetails);

	    	ServletUtils.getInstance().generateMessage(request, "The script has been deleted.");
    	} catch(SQLException sqle) {
    		request.setAttribute("error_page", "/admin/IntegrationModuleScripts");
    		throw new ServletException("The script could not be deleted at the current time.", sqle);
    	}
    	response.sendRedirect(response.encodeRedirectURL("/admin/IntegrationModuleScripts"));
    }

    @Override
	public String getServletInfo() {
        return "Retrieves the script if needed and sends the user to the editing screen";
    }
}
