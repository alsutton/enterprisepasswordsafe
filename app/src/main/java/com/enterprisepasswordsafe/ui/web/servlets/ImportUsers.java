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

import com.enterprisepasswordsafe.database.Group;
import com.enterprisepasswordsafe.model.dao.GroupDAO;
import com.enterprisepasswordsafe.model.dao.UserDAO;
import com.enterprisepasswordsafe.engine.users.UserImporter;
import com.enterprisepasswordsafe.engine.users.UserPriviledgeTransitioner;
import com.enterprisepasswordsafe.ui.web.utils.PasswordGenerator;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import org.apache.commons.csv.CSVRecord;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

public final class ImportUsers extends ImporterServlet {

    @Override
	public String getServletInfo() {
        return "Imports groups into the database.";
    }

    @Override
	public void importEntry(HttpServletRequest request, final User theUser, final String parentNode,
							CSVRecord record)
    	throws ServletException {
    	Group adminGroup = (Group)request.getAttribute("adminGroup");
    	try {
    		new UserImporter(UserDAO.getInstance(), new UserPriviledgeTransitioner())
    			.importData(theUser, adminGroup, PasswordGenerator.getInstance(), record);
    	} catch(Exception ex) {
    		throw new ServletException("There was a problem importing the users", ex);
    	}
    }

    @Override
	protected void setImportAttributes(final HttpServletRequest request)
    	throws ServletException {
    	User thisUser = SecurityUtils.getRemoteUser(request);
    	try {
    		Group adminGroup = GroupDAO.getInstance().getAdminGroup(thisUser);
        	request.setAttribute("adminGroup", adminGroup);
    	} catch(Exception ex) {
    		throw new ServletException("There was a problem importing the users", ex);
    	}
    }
}
