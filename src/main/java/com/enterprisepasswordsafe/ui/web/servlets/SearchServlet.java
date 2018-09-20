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
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.HierarchyNode;
import com.enterprisepasswordsafe.engine.database.HierarchyNodeDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.database.actions.PasswordSearchAction;
import com.enterprisepasswordsafe.engine.database.actions.search.NotesContainsSearchTest;
import com.enterprisepasswordsafe.engine.database.actions.search.SearchTest;
import com.enterprisepasswordsafe.engine.database.actions.search.SystemContainsSearchTest;
import com.enterprisepasswordsafe.engine.database.actions.search.UsernameContainsSearchTest;
import com.enterprisepasswordsafe.engine.hierarchy.HierarchyTools;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;

public class SearchServlet extends HttpServlet {

    private final HierarchyTools hierarchyTools = new HierarchyTools();

    @Override
    protected void doGet(final HttpServletRequest request,
                         final HttpServletResponse response) throws ServletException, IOException {
        request.getRequestDispatcher("/system/adv_search.jsp").forward(request, response);
    }

    @Override
    protected final void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        try {
            User thisUser = SecurityUtils.getRemoteUser(request);
            PasswordSearchAction search = new PasswordSearchAction(thisUser, getSearchTests(request));

            HierarchyNode node = null;
            String searchAll = request.getParameter("searchall");

            HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
            if( searchAll == null || searchAll.length() == 0 ) {
                String nodeId = (String) request.getSession(false).getAttribute("nodeId");
                if( nodeId != null ) {
                    node = hnDAO.getById(nodeId);
                }
            }
            if( node == null ) {
                request.setAttribute("searchAll", Boolean.TRUE);
                node = hnDAO.getById(HierarchyNode.ROOT_NODE_ID);
            }

            hierarchyTools.processObjectNodes(node, thisUser, search, true);

            request.setAttribute("passwordmap", search.getResults());
            request.setAttribute("resultcount", Integer.toString(search.getResultCount()));
        } catch(Exception ex) {
            request.setAttribute("error_page", "/system/adv_search.jsp");
            throw new ServletException("The passwords could not be found due to an error.", ex);
        }

        request.getRequestDispatcher("/system/adv_search.jsp").forward(request, response);
    }


    protected List<SearchTest> getSearchTests(final HttpServletRequest request) {
        List<SearchTest> tests = new ArrayList<>();

        String searchString = request.getParameter("username");
        if (searchString != null && searchString.length() > 0) {
            tests.add(new UsernameContainsSearchTest(searchString));
        }

        searchString = request.getParameter("system");
        if (searchString != null && !searchString.isEmpty()) {
            tests.add(new SystemContainsSearchTest(searchString));
        }

        searchString = request.getParameter("notes");
        if (searchString != null && searchString.length() > 0) {
            tests.add(new NotesContainsSearchTest(searchString));
        }

        return tests;
    }

    public String getServletInfo() {
        return "Searches for a password given a specified set of criteria.";
    }

}
