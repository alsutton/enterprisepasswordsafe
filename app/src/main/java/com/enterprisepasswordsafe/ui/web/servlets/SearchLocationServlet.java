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

import com.enterprisepasswordsafe.database.Password;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Searches for all the passwords in a specific location.
 */

public final class SearchLocationServlet extends SearchServlet {

    /**
     * This servlet is usually called with a GET
     */

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
        throws ServletException, IOException {
        doPost(request, response);
    }

	/**
     * Search for all passwords with a specific location.
     *
     * @see com.enterprisepasswordsafe.ui.web.servlets.SearchServlet#getSearchTests(javax.servlet.http.HttpServletRequest)
     */
    @Override
    protected List<Predicate<Password>> getSearchTests(final HttpServletRequest request) {
        final String location = request.getParameter("location");
        if(location == null) {
            return List.of();
        }
        List<Predicate<Password>> tests = new ArrayList<>();
        tests.add(password -> password.getLocation() != null && password.getLocation().equalsIgnoreCase(location));
        return tests;
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    public String getServletInfo() {
        return "Searches for passwords in a specific location";
    }

}
