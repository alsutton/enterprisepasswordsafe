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

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.integration.PasswordChanger;
import com.enterprisepasswordsafe.ui.web.utils.PasswordGenerator;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;

public final class RandomizePassword extends HttpServlet {

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

	    	PasswordDAO pDAO = PasswordDAO.getInstance();
	    	final Password password = pDAO.getById(passwordId, ac);


	    	// Create the password changing properties.
	    	final Map<String,String> passwordProperties = new HashMap<>();
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
	        pDAO.update(password, user, ac);

	        TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
	        				user, password, "Randomized the password.",
	        				password.getAuditLevel().shouldTriggerEmail());
	        ServletUtils.getInstance().generateMessage(request, "The password has been changed.");
	    } catch(Exception ex) {
	    	throw new ServletException("There was a problem talking to the system holding the password.", ex);
	    }

    	request.getRequestDispatcher(ServletPaths.getExplorerPath()).forward(request, response);
    }

    @Override
	public String getServletInfo() {
        return "Servlet to alter the scripts associated with a password";
    }
}
