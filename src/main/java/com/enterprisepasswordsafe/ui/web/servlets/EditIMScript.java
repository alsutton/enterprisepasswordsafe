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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class EditIMScript extends EditIMScriptBase {

	@Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	try {
			String scriptId = request.getParameter("scriptid");
			IntegrationModuleScript scriptDetails = IntegrationModuleScriptDAO.getInstance().getById(scriptId);
			if( scriptDetails == null ) {
				throw new ServletException("The chosen script does not exist.");
			}

	    	handleRequest(request, scriptDetails);
    	} catch(Exception ex) {
    		request.setAttribute("error_page", "/admin/IntegrationModuleScripts");
    		throw new ServletException("The listy of scripts are unavailable at the current time.", ex);
    	}

    	request.getRequestDispatcher("/admin/im_scripts_edit.jsp").forward(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Sends the user to the editing screen";
    }
}
