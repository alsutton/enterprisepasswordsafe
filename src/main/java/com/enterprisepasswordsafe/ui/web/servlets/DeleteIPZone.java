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

import java.io.IOException;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.IPZone;
import com.enterprisepasswordsafe.engine.database.IPZoneDAO;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public final class DeleteIPZone extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = 7784300056789406798L;

    /**
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        String id = request.getParameter("zoneid");
        try {
        	IPZoneDAO ipzDAO = IPZoneDAO.getInstance();
	        IPZone thisZone = ipzDAO.getById(id);
	        if( thisZone == null ) {
	            throw new ServletException( "The zone is not available." );
	        }
	        ipzDAO.delete(thisZone);
	        ServletUtils.getInstance().generateMessage(request, "The network zone was deleted.");
        } catch(SQLException sqle) {
        	request.setAttribute("error_page", "/admin/EditIPZones");
        	throw new ServletException("The IP zone could not be deleted." ,sqle);
        }
        response.sendRedirect(response.encodeRedirectURL("/admin/EditIPZones"));
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Servlet to delete an IP Zone to edit.";
    }
}
