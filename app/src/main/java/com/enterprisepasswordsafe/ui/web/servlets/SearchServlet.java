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

import com.enterprisepasswordsafe.engine.hierarchy.HierarchyTools;
import com.enterprisepasswordsafe.model.dao.HierarchyNodeDAO;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.passwordprocessor.actions.PasswordSearchAction;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

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


    protected List<Predicate<Password>> getSearchTests(final HttpServletRequest request) {
        List<Predicate<Password>> tests = new ArrayList<>();
        addUsernameTestIfNeeded(request, tests);
        addSystemTestIfNeeded(request, tests);
        addNotesTestIfNeeded(request, tests);
        return tests;
    }

    private void addUsernameTestIfNeeded(final HttpServletRequest request, List<Predicate<Password>> tests) {
        final String searchString = request.getParameter("username");
        if (searchString == null || searchString.length() == 0) {
            return;
        }

        tests.add(password -> isNonNullAndContains(password.getUsername(), searchString));
    }

    private void addSystemTestIfNeeded(final HttpServletRequest request, List<Predicate<Password>> tests) {
        final String searchString = request.getParameter("system");
        if (searchString == null || searchString.length() == 0) {
            return;
        }

        tests.add(password -> isNonNullAndContains(password.getLocation(), searchString));
    }

    private void addNotesTestIfNeeded(final HttpServletRequest request, List<Predicate<Password>> tests) {
        final String searchString = request.getParameter("notes");
        if (searchString == null || searchString.length() == 0) {
            return;
        }

        tests.add(password -> isNonNullAndContains(password.getNotes(), searchString));
    }

    private boolean isNonNullAndContains(String actual, String search) {
        return actual != null && actual.toLowerCase().contains(search);
    }

    public String getServletInfo() {
        return "Searches for a password given a specified set of criteria.";
    }

}
