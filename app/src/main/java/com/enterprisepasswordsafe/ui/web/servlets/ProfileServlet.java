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

import com.enterprisepasswordsafe.engine.utils.PasswordRestrictionUtils;
import com.enterprisepasswordsafe.model.dao.UserDAO;
import com.enterprisepasswordsafe.ui.web.servletfilter.AuthenticationFilter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;


/**
 * Servlet to update a users login password.
 */

public final class ProfileServlet extends HttpServlet {
    /**
     * The parameter used when the change of password is forced.
     */

    public static final String FORCED_CHANGE_PARAMETER = "forced";

    /**
     * The attribute for the text showing the current password controls in
     * place.
     */

    public static final String CONTROL_TEXT_ATTRIBUTE = "control_text";

    /**
     * The next page to send the user to if the change was not forced.
     */

    private static final String REQUESTED_NEXT_PAGE = "/system/profile.jsp";

    /**
     * The next page to send the user to if the change was forced.
     */

    private static final String FORCED_NEXT_PAGE = "/nomenu/forced_update_login_password.jsp";

    /**
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
        String nextPage;
        if(request.getSession().getAttribute(FORCED_CHANGE_PARAMETER) != null) {
            nextPage = FORCED_NEXT_PAGE;
        } else {
            nextPage = REQUESTED_NEXT_PAGE;
        }

        try {
            PasswordRestrictionUtils control =
                    PasswordRestrictionDAO.getInstance().getById(PasswordRestrictionUtils.LOGIN_PASSWORD_RESTRICTION_ID);

            String controlString = "";
            if(control != null) {
                controlString = control.toString();
            }
            request.setAttribute(CONTROL_TEXT_ATTRIBUTE, controlString);
        } catch(SQLException sqle) {
            throw new ServletException("You can not change your password at the current time.", sqle);
        }

        request.getRequestDispatcher(nextPage).forward(request, response);
    }

    /**
     * @see HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
        String csrfToken = request.getParameter("token");
        if(csrfToken == null
        || !csrfToken.equals(request.getSession(true).getAttribute("csrfToken"))) {
            throw new ServletException("Permission Denied");
        }

        User thisUser = SecurityUtils.getRemoteUser(request);
        try {
	        String currentPassword = request.getParameter("currentpassword");
	        if (!thisUser.checkPassword(currentPassword)) {
	            throw new ServletException("The current password was not entered correctly.");
	        }

	        String password1 = request.getParameter("password1");
	        String password2 = request.getParameter("password2");
	        if (!password1.equals(password2)) {
	            throw new ServletException("The passwords you entered were not the same.");
	        }

	        if (thisUser.checkPassword(password1)) {
	        	throw new ServletException("Your new password must not be the same as your old one.");
	        }

	    	PasswordRestrictionUtils control =
	    		PasswordRestrictionDAO.getInstance().getById(PasswordRestrictionUtils.LOGIN_PASSWORD_RESTRICTION_ID);
	        if (control != null && !control.verify(password1)) {
	            throw new ServletException(
	                    "Your password has NOT been updated because the new password does not meet the minimum requirements ("
	                    	+ control.toString()
	                    +").");
	        }

	    	UserDAO.getInstance().updatePassword(thisUser, password1);
	        request.getSession().setAttribute(
	                AuthenticationFilter.ACCESS_KEY_PARAMETER,
	                thisUser.getAccessKey()
	            );
	        ServletUtils.getInstance().generateMessage(request, "Your password was updated");
	        request.getSession().removeAttribute(FORCED_CHANGE_PARAMETER);
        } catch(SQLException | GeneralSecurityException sqle) {
        	throw new ServletException("The password could not be updated due to an error.", sqle);
        }

        response.sendRedirect(request.getContextPath()+"/system/Profile");
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Updates the users login password";
    }

}
