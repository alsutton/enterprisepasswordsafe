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
import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.AccessControl;
import com.enterprisepasswordsafe.engine.database.AccessControlDAO;
import com.enterprisepasswordsafe.engine.database.BOMFactory;
import com.enterprisepasswordsafe.engine.database.IntegrationModule;
import com.enterprisepasswordsafe.engine.database.IntegrationModuleConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.IntegrationModuleDAO;
import com.enterprisepasswordsafe.engine.database.IntegrationModuleScript;
import com.enterprisepasswordsafe.engine.database.IntegrationModuleScriptDAO;
import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.engine.database.PasswordDAO;
import com.enterprisepasswordsafe.engine.database.PasswordRestriction;
import com.enterprisepasswordsafe.engine.database.PasswordRestrictionDAO;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLog;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLogDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.integration.PasswordChanger;
import com.enterprisepasswordsafe.ui.web.utils.PasswordGenerator;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

/**
 * Servlet to run the integration scripts
 */
public final class RandomizePassword extends HttpServlet {

    /**
     * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
        throws ServletException, IOException {
    	try {
	    	final User user = SecurityUtils.getRemoteUser(request);
	    	final String passwordId = request.getParameter("id");
	    	final AccessControl ac = AccessControlDAO.getInstance().getAccessControl(user, passwordId);
	    	if( ac == null ) {
	    		throw new ServletException( "You do not have access to this password.");
	    	}
	    	if( ac.getModifyKey() == null ) {
	    		throw new ServletException( "You do not have modification rights to the password.");
	    	}
	    	final Password password = PasswordDAO.getInstance().getById(ac, passwordId);


	    	// Create the password changing properties.
	    	final Map<String,String> passwordProperties = new HashMap<String,String>();
			passwordProperties.put(PasswordChanger.USERNAME_PROPERTY, password.getUsername());
			passwordProperties.put(PasswordChanger.SYSTEM, password.getLocation());
			passwordProperties.put(PasswordChanger.OLD_PASSWORD, password.getPassword());

			PasswordRestrictionDAO prDAO = PasswordRestrictionDAO.getInstance();
	        PasswordRestriction control = prDAO.getById(password.getRestrictionId());
	        if( control == null ) {
	        	control = prDAO.getById(PasswordRestriction.MIGRATED_RESTRICTION_ID);
	        }
	        String newPassword = PasswordGenerator.getInstance().generate(control, true);
	        passwordProperties.put(PasswordChanger.NEW_PASSWORD, newPassword);

			// Run through the scripts activating them
	        final IntegrationModuleDAO imDAO = IntegrationModuleDAO.getInstance();
	        final IntegrationModuleConfigurationDAO imcDAO = IntegrationModuleConfigurationDAO.getInstance();
	        final Connection dbConnection = BOMFactory.getCurrentConntection();
	        for(IntegrationModuleScript thisScript : IntegrationModuleScriptDAO.getInstance().getScriptsForPassword(password.getId())) {
	    		final Map<String,String> scriptProperties = imcDAO.getProperties(thisScript, password);
	    		final IntegrationModule module = imDAO.getById(thisScript.getModuleId());
	    		final PasswordChanger changer = imDAO.getPasswordChangerInstance(module);
	    		changer.changePassword( dbConnection, scriptProperties, passwordProperties, thisScript.getScript() );
	    	}

	    	password.setPassword(newPassword);
	        PasswordDAO.getInstance().update(password, user, ac);

	        TamperproofEventLogDAO.getInstance().create(
	        				TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
	        				user,
	        				password,
	        				"Randomized the password.",
	        				((password.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0)
	    				);
	        ServletUtils.getInstance().generateMessage(request, "The password has been changed.");
	    } catch(Exception ex) {
	    	throw new ServletException("There was a problem talking to the system holding the password.", ex);
	    }

    	request.getRequestDispatcher(ServletPaths.getExplorerPath()).forward(request, response);
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Servlet to alter the scripts associated with a password";
    }
}
