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

package com.enterprisepasswordsafe.ui.web.rawapi;

import com.enterprisepasswordsafe.database.PasswordDAO;
import com.enterprisepasswordsafe.database.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Servlet to list the authentication sources.
 */

public final class FindIds extends RawAPIServlet {

    @Override
	protected void doPost(final HttpServletRequest request, HttpServletResponse response)
    	throws IOException {

    	try {
    		User theUser = super.getAndAuthenticateUser(request);
    		String searchUsername = request.getParameter("searchUsername");
    		String searchLocation = request.getParameter("searchSystem");
    		Set<String> ids = PasswordDAO.getInstance().performRawAPISearch(theUser, searchUsername, searchLocation);

    		response.setContentType("text/plain");
            response.setCharacterEncoding("UTF-8");
    		PrintWriter writer = response.getWriter();
    		Iterator<String> idIter = ids.iterator();
    		while(idIter.hasNext()) {
    			writer.print(idIter.next());
    			if( idIter.hasNext() )
    				writer.print(",");
    		}
    	} catch( Exception ex ) {
    		Logger.getAnonymousLogger().log(Level.WARNING,"Error during FindPassword",ex);
    		response.sendError(HttpServletResponse.SC_BAD_REQUEST);
    	}
    }



    @Override
	public String getServletInfo() {
        return "Raw API Servlet to find a password id from a x@y format";
    }
}
