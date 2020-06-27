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

/*
 * Filter.java
 *
 * Created on 22 July 2003, 12:09
 */

package com.enterprisepasswordsafe.ui.web.servletfilter;

import com.enterprisepasswordsafe.ui.web.servlets.BaseServlet;
import com.enterprisepasswordsafe.ui.web.utils.IDGenerator;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


/**
 * Filter to handle authentication of the user and session before allowing access
 * to the system resources.
 */

public final class AuthenticationFilter implements Filter {
    /**
     * The parameter used to hold the users access key.
     */

    public static final String USER_NAME_PARAMETER = "user_name";

    /**
     * The session parameter for the user type.
     */

    public static final String USER_TYPE_PARAMETER = "user_type";

    /**
     * The flag to say a user is an administrator.
     */

    public static final String USER_IS_ADMIN = "user_is_admin";

    /**
     * The flag to say the user is a sub-administrator.
     */

    public static final String USER_IS_SUBADMIN = "user_is_subadmin";

    /**
     * The types of user.
     */

    public static final String  NORMAL_USER = "N",
                                SUB_ADMIN = "P",
                                FULL_ADMIN = "E";

    /**
     * The parameter used to hold the users access key.
     */

    public static final String ACCESS_KEY_PARAMETER = "access_key";

    /**
     * The session timeout error message.
     */

    private static final String SESSION_TIMEOUT_ERROR = "Your session timed out. Please login again.";

    /**
     * Initialise the filter by extracting the servlet context and storing it
     * for later use.
     *
     * @param config The configuration of the filter.
     */
    @Override
	public void init(final FilterConfig config) {
    	// Do nothing.
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
            FilterChain next) throws ServletException {
        try {
	        HttpServletRequest req = (HttpServletRequest) request;
	        HttpServletResponse res = (HttpServletResponse) response;

	        // Don't run the filter for any of the system pages
	        HttpSession session = req.getSession();

	        if( session.getAttribute(USER_TYPE_PARAMETER) == null ) {
	        	redirectToLoginScreen(session, req, res);
	        	return;
	        }

        	String nextOtid = IDGenerator.getID();
        	request.setAttribute("nextOtid", nextOtid);
            next.doFilter(request, response);

            // NOTE: The reason this gets from the request attribute is that
            // some servlets pack re-use the otid to avoid problems with
            // ViewPassword (look at ViewPasswordImage)
            try {
            	session.setAttribute("otid", request.getAttribute("nextOtid"));
            } catch( IllegalStateException ise ) {
                // Ignore the ISE, it means the session is being bailed out on.
            }
        } catch (Exception ex) {
        	throw new ServletException("Error in auth filter", ex);
        }
    }

	/**
	 * Redirect the user to the login screen
	 */

	private void redirectToLoginScreen(final HttpSession session,
			final HttpServletRequest request, final HttpServletResponse response)
		throws IOException {
        ServletUtils.getInstance().generateErrorMessage(request, SESSION_TIMEOUT_ERROR);
        session.setAttribute(BaseServlet.ORIGINAL_URI, request.getRequestURL().toString());

		Map<String,String[]> parameters = request.getParameterMap();
        if( parameters != null ) {
        	Map<String,String> paramMap = new HashMap<String,String>();
        	for(Map.Entry<String,String[]> thisEntry : parameters.entrySet()) {
        		String paramName = thisEntry.getKey();
        		paramMap.put(paramName, request.getParameter(paramName));
        	}
        	session.setAttribute(BaseServlet.ORIGINAL_PARAMETERS, paramMap);
        }

        response.sendRedirect(request.getContextPath()+"/Login");
	}

    /**
     * @see javax.servlet.Filter#destroy()
     */

    @Override
	public void destroy() {
    	// No long-lasting resources.
    }
}
