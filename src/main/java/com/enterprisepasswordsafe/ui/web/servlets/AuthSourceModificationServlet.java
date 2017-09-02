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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

/**
 * Base class for servlets modifing the parameters of an authentication source.
 */

public abstract class AuthSourceModificationServlet extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = -3959964222349333403L;

	/**
     * The prefix for property names which are part of the authentication
     * source.
     */

    private static final String PROPERTY_NAME_PREFIX = "auth_";

    /**
     * The length of property name prefix.
     */

    private static final int PROPERTY_NAME_PREFIX_LENGTH = PROPERTY_NAME_PREFIX.length();

    /**
     * Extracts the authentication parameters from the servlet request.
     *
     * @param request
     *            The servlet request to extract the parameters from.
     *
     * @return The Map of parameters.
     */

	protected final Map<String,String> extractAuthParameters(final HttpServletRequest request) {
        Map<String,String> authParams = new HashMap<String,String>();

        for(Map.Entry<String,String[]> thisEntry : request.getParameterMap().entrySet()) {
            if (thisEntry.getKey().startsWith(PROPERTY_NAME_PREFIX)) {
                String key = thisEntry.getKey();
                String subKey = key.substring(PROPERTY_NAME_PREFIX_LENGTH);
                authParams.put(subKey, request.getParameter(key));
            }
        }

        return authParams;
    }

}
