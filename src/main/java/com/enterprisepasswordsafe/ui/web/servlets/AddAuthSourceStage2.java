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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.jaas.ActiveDirectoryDomainLoginModule;
import com.enterprisepasswordsafe.engine.jaas.ActiveDirectoryLoginModule;
import com.enterprisepasswordsafe.engine.jaas.ActiveDirectoryNonAnonymousLoginModule;
import com.enterprisepasswordsafe.engine.jaas.AuthenticationSourceModule;
import com.enterprisepasswordsafe.engine.jaas.EPSJAASConfiguration;
import com.enterprisepasswordsafe.engine.jaas.JndiLoginModuleDummy;
import com.enterprisepasswordsafe.engine.jaas.LDAPLoginModule;
import com.enterprisepasswordsafe.engine.jaas.LDAPSearchAndBindLoginModule;


/**
 * Servlet to list the authentication sources.
 */

public final class AddAuthSourceStage2 extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = 5163634891845316398L;

    /**
     * @see HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
    	request.setAttribute("error_page", "/admin/AuthSources");

    	String type = request.getParameter("type");
    	request.setAttribute("type", type);
    	AuthenticationSourceModule module;

        if (type.equals(EPSJAASConfiguration.LDAP_APPLICATION_CONFIGURATION)) {
        	module = new LDAPLoginModule();
        } else if (type.equals(EPSJAASConfiguration.RFC2307_APPLICATION_CONFIGURATION)) {
        	module = new JndiLoginModuleDummy();
        } else if (type.equals(EPSJAASConfiguration.LDAP_SANDB_APPLICATION_CONFIGURATION)) {
        	module = new LDAPSearchAndBindLoginModule();
        } else if (type.equals(EPSJAASConfiguration.AD_APPLICATION_CONFIGURATION)) {
        	module = new ActiveDirectoryLoginModule();
        } else if (type.equals(EPSJAASConfiguration.AD_NONANON_APPLICATION_CONFIGURATION)) {
        	module = new ActiveDirectoryNonAnonymousLoginModule();
	    } else if (type.equals(EPSJAASConfiguration.AD_DOMAIN_APPLICATION_CONFIGURATION)) {
	    	module = new ActiveDirectoryDomainLoginModule();
	    } else {
	    	throw new ServletException("Unknown source type.");
	    }

        request.setAttribute("name", "");
        request.setAttribute("id", "");
    	request.setAttribute("parameters", module.getConfigurationOptions());
    	request.setAttribute("notes", module.getConfigurationNotes());

        request.getRequestDispatcher("/admin/add_authsource_configure.jsp").forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Servlet to add an authentication source to the list of available sources";
    }
}
