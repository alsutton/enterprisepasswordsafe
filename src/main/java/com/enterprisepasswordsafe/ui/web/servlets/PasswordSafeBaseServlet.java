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

import javax.servlet.http.HttpServletRequest;



public abstract class PasswordSafeBaseServlet extends BaseServlet {

	/**
	 * Generated Serial ID
	 */
	private static final long serialVersionUID = -7529067864534335389L;

    /**
     * Gets the ID of the node the user is currently at.
     * 
     * @param request The request being serviced.
     * 
     * @return The ID of the node the user is currently viewing.
     */
	
	public String getCurrentNodeId(HttpServletRequest request) {
		return (String) request.getSession(true).getAttribute("nodeId");
	}
	
    /**
     * Sets the ID of the node the user is currently at.
     * 
     * @param request The request being serviced.
     * @param nodeId The ID of the node the user is currently at.
     */
	
	public void setCurrentNodeId(HttpServletRequest request, String nodeId) {
		request.getSession(true).setAttribute("nodeId", nodeId);
	}
	
}
