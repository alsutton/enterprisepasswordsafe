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
import com.enterprisepasswordsafe.engine.hierarchy.HierarchyTools;
import com.enterprisepasswordsafe.engine.passwords.PasswordImporter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;
import org.apache.commons.csv.CSVRecord;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.List;

public final class ImportPasswords extends ImporterServlet {

    @Override
	public String getServletInfo() {
        return "Imports passwords into the database.";
    }

    @Override
	public void importEntry(HttpServletRequest request, final User theUser, final String parentNode,
							CSVRecord record) throws ServletException {
    	Group adminGroup = (Group)request.getAttribute("adminGroup");
    	try {
			new PasswordImporter(adminGroup).importPassword(theUser, parentNode, record);
		} catch (SQLException | GeneralSecurityException | IOException e) {
        	throw new ServletException("Password import failed", e);
		}
    }

    /**
     * @see ImporterServlet#setImportAttributes(javax.servlet.http.HttpServletRequest)
     */
    @Override
	protected void setImportAttributes(final HttpServletRequest request) throws ServletException {
        String nodeId = ServletUtils.getInstance().getNodeId(request);

        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
		HierarchyTools hierarchyTools = new HierarchyTools();
        try {
	        HierarchyNode node = hnDAO.getById(nodeId);
	        List<HierarchyNode> parentage = hierarchyTools.getParentage(node);
	        request.setAttribute(BaseServlet.NODE, node);
	        request.setAttribute(BaseServlet.NODE_PARENTAGE, parentage);
        } catch(SQLException sqle) {
        	throw new ServletException("Password import failed", sqle);
        }

    	User thisUser = SecurityUtils.getRemoteUser(request);
    	try {
    		Group adminGroup = GroupDAO.getInstance().getAdminGroup(thisUser);
        	request.setAttribute("adminGroup", adminGroup);
    	} catch(Exception ex) {
        	throw new ServletException("Password import failed", ex);
    	}
    }

}
