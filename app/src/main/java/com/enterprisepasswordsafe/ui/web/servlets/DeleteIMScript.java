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

import com.enterprisepasswordsafe.model.dao.IntegrationModuleConfigurationDAO;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;


/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class DeleteIMScript extends HttpServlet {

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	final String scriptId = request.getParameter("scriptid");
    	try {
	    	if( ! IntegrationModuleConfigurationDAO.getInstance().scriptIsInUse(scriptId) ) {
	    		request.getRequestDispatcher("/admin/DeleteIMScriptStage2").forward(request, response);
	    	} else {
	    		request.getRequestDispatcher("/admin/im_script_confirm_delete.jsp").forward(request, response);
	    	}
    	} catch(SQLException sqle) {
    		request.setAttribute("error_page", "/admin/IntegrationModuleScripts");
    		throw new ServletException("The script can not be deleted at this time.", sqle);
    	}
    }

    @Override
	public String getServletInfo() {
        return "Checks to see if a script is in use, if it isn't then delete it.";
    }
}
