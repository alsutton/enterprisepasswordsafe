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

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.Group;
import com.enterprisepasswordsafe.engine.database.GroupDAO;
import com.enterprisepasswordsafe.engine.database.HierarchyNode;
import com.enterprisepasswordsafe.engine.database.PasswordDAO;
import com.enterprisepasswordsafe.engine.database.User;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

public final class CreatePassword extends RawAPIServlet {

    @Override
	protected void doPost(final HttpServletRequest request, HttpServletResponse response)
    	throws IOException {
    	try {
    		User user = super.getAndAuthenticateUser(request);

    		String data = request.getParameter("passwordData");
    		if( data == null ) {
    			throw new RuntimeException("Data not specified");
    		}

    		final Group adminGroup = GroupDAO.getInstance().getAdminGroup(user);

			CSVParser parser = CSVParser.parse(data, CSVFormat.RFC4180);
			for(CSVRecord record : parser) {
				PasswordDAO.getInstance().importPassword(user, adminGroup, HierarchyNode.ROOT_NODE_ID, record);
			}
    	} catch( Exception ex ) {
    		Logger.getAnonymousLogger().log(
    				Level.WARNING,
    				"Error during GetPassword",
    				ex
				);
    		response.sendError(HttpServletResponse.SC_BAD_REQUEST);
    	}
    }

    @Override
	public String getServletInfo() {
        return "Raw API Servlet to create a password.";
    }
}
