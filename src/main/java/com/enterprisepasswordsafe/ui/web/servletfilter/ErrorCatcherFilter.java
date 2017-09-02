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

package com.enterprisepasswordsafe.ui.web.servletfilter;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

/**
 * Filter to handle authentication of the user and session before allowing access
 * to the system resources.
 */

public final class ErrorCatcherFilter implements Filter {
    /**
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
    @Override
	public void init(final FilterConfig config) {
    	// No init needed
    }

    /**
     * Filter to check the user and session are valid before allowing access to
     * the main system.
     *
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
     *      javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */

    @Override
	public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain next) throws IOException, ServletException {
        try {
        	next.doFilter(request, response);
        } catch(ServletException e) {
        	Logger.getAnonymousLogger().log(Level.SEVERE, e.getMessage(), e);

        	HttpServletRequest req = (HttpServletRequest) request;
        	ServletUtils.getInstance().generateErrorMessage(req, e.getMessage());
        	String forward = (String) request.getAttribute("error_page");
        	if(forward == null) {
        		if(request.getAttribute("isInExplorer") == null) {
        			forward = ServletPaths.getExplorerPath();
        		} else {
        	    	SecurityUtils.clearLoggedInUserDetails(req);
        			forward = "";
        		}
        	}

        	((HttpServletResponse)response).sendRedirect(req.getContextPath()+forward);
        }
    }

    /**
     * @see javax.servlet.Filter#destroy()
     */

    @Override
	public void destroy() {
    	// No long-lasting resources.
    }
}
