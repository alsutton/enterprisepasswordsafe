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

import com.enterprisepasswordsafe.database.ConfigurationDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;


/**
 * Servlet to send the user to the page allowing them to edit the default custom fields for a password.
 */

public final class StoreCustomFields extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = -5130185999368612035L;

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletResponse)
     */
    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	try {
	    	String action = request.getParameter("action");

	    	int i = 0;
	    	int counter = 0;
	    	String fieldName, fieldValue;
	    	ConfigurationDAO cDAO = ConfigurationDAO.getInstance();
	    	while( (fieldName = request.getParameter("fn_"+counter)) != null ) {
	    		fieldValue = request.getParameter("fv_"+counter);
	    		String deleteFlag = request.getParameter("fdel_"+counter);
	    		counter++;

	    		if( deleteFlag != null && deleteFlag.length() > 0 )
	    			continue;


	    		cDAO.set("custom_fn"+i, fieldName);
	    		cDAO.set("custom_fv"+i, fieldValue);
	    		i++;
	    	}

	    	if( action != null && action.equals("add") ) {
	    		StringBuffer fieldNameBuffer = new StringBuffer("custom_fn");
	    		if( i < 10 ) {
	    			fieldNameBuffer.append('0');
	    		}
	    		fieldNameBuffer.append(i+1);
	    		cDAO.set("custom_fn"+i, fieldNameBuffer.toString());
	    		cDAO.set("custom_fv"+i, "Default Value");
	    		i++;
	    	}

	    	cDAO.set("custom_fn"+i, null);
	    	cDAO.set("custom_fv"+i, null);

			ServletUtils.getInstance().generateMessage(request, "The custom fields have been updated");
			if( action != null && action.equals("add") ) {
				response.sendRedirect(request.getContextPath()+"/admin/CustomFields");
			} else {
				response.sendRedirect(request.getContextPath()+ServletPaths.getExplorerPath());
			}
	    } catch(SQLException sqle) {
	    	throw new ServletException("The custom fields can not be altered at this time.", sqle);
	    }
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Servlet to allow the user to edit the default custom fields.";
    }
}
