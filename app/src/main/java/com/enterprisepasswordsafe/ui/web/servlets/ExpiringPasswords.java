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

import com.enterprisepasswordsafe.model.dao.PasswordDAO;
import com.enterprisepasswordsafe.database.derived.ExpiringAccessiblePasswords;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;


/**
 * Servlet to direct the user to the expiring passwords page.
 */

public final class ExpiringPasswords extends HttpServlet {

    /**
     * @see HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
	@Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
		throws ServletException, IOException {
        User user = SecurityUtils.getRemoteUser(request);

        ExpiringAccessiblePasswords expiringPasswords;
        try {
        	expiringPasswords = PasswordDAO.getInstance().getExpiringPasswords(user);
        } catch(Exception ex) {
    		throw new ServletException("There was a problem attempting to fetch the expiring passwords.");
        }

        Set<Password> expiringPasswordsSet = expiringPasswords.getExpiring();
        if( expiringPasswordsSet != null && expiringPasswordsSet.size() > 0 ) {
        	request.setAttribute("passwords_expiring", expiringPasswordsSet );
        	request.setAttribute("passwords_expiring_count", Integer.toString(expiringPasswordsSet.size()) );
        }

        Set<Password> expiredPasswordsSet = expiringPasswords.getExpired();
        if( expiredPasswordsSet != null && expiredPasswordsSet.size() > 0 ) {
        	request.setAttribute( "passwords_expired", expiredPasswordsSet );
        	request.setAttribute( "passwords_expired_count", Integer.toString(expiredPasswordsSet.size()) );
        }

        request.getRequestDispatcher("/system/expiring_passwords.jsp").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Obtains the data neccessary to show the expiring passwords screen.";
    }

}
