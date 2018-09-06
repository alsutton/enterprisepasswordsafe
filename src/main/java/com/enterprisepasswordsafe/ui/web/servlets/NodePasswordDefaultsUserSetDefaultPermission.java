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

import com.enterprisepasswordsafe.engine.database.HierarchyNodePermissionDAO;
import com.enterprisepasswordsafe.engine.database.UserSummaryDAO;
import com.enterprisepasswordsafe.engine.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.nodes.UserNodeDefaultPermission;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class NodePasswordDefaultsUserSetDefaultPermission extends HttpServlet {
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setHeader("Cache-Control","no-cache"); //HTTP 1.1
		response.setHeader("Pragma","no-cache"); //HTTP 1.0
		response.setDateHeader ("Expires", 0);

		try {
			List<UserNodeDefaultPermission> results= new ArrayList<UserNodeDefaultPermission>();

			final String searchQuery = request.getParameter("s");
			if(searchQuery != null && !searchQuery.isEmpty()) {
				final String nodeId = ServletUtils.getInstance().getNodeId(request);

				HierarchyNodePermissionDAO hnDAO = new HierarchyNodePermissionDAO();
				for(UserSummary user : UserSummaryDAO.getInstance().getSummaryBySearch(searchQuery)) {
					results.add(hnDAO.getDefaultPermissionForUser(user, nodeId));
				}
			}

			request.setAttribute("results",results);
			request.getRequestDispatcher("/subadmin/edit_subnodes_pdefaults_usearchresults.jsp").forward(request, response);
		} catch(SQLException sqle) {
			Logger.getAnonymousLogger().log(Level.WARNING, "Error during user search", sqle);
		}
	}

}
