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

import com.enterprisepasswordsafe.database.IntegrationModule;
import com.enterprisepasswordsafe.database.IntegrationModuleConfigurationDAO;
import com.enterprisepasswordsafe.database.IntegrationModuleDAO;
import com.enterprisepasswordsafe.database.IntegrationModuleScript;
import com.enterprisepasswordsafe.engine.integration.PasswordChangerProperty;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;


/**
 * Servlet to send the user to the page to list the authentication sources.
 */

public abstract class EditIMScriptBase extends HttpServlet {
    /**
	 *
	 */
	private static final long serialVersionUID = -7293993712243707875L;

    /**
     * Method to populate the details of the request.
     */

    protected void handleRequest(final HttpServletRequest request, final IntegrationModuleScript scriptDetails)
    	throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
    	IntegrationModule module =
    		IntegrationModuleDAO.getInstance().getById(scriptDetails.getModuleId());

    	request.setAttribute( "module", module );
		request.setAttribute( "scriptobj", scriptDetails);
    	request.setAttribute(
    			"properties",
    			getCurrentPropertySettings(request,module,scriptDetails)
			);
    }

    /**
     * Populate a Set with objects containing the display name, internal name, and
     * current value of the integration module properties.
     *
     * @param bom The business object manager.
     * @throws IllegalAccessException
     * @throws InstantiationException
     * @throws ClassNotFoundException
     */

    public Set<ScriptProperties> getCurrentPropertySettings(
    		final HttpServletRequest request,
    		final IntegrationModule module,
    		final IntegrationModuleScript scriptDetails)
    	throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException{
    	final Set<ScriptProperties> properties = new TreeSet<>();

    	Map<String,String> currentProperties = IntegrationModuleConfigurationDAO.
    											getInstance().
								    				getProperties(scriptDetails, null);

    	for(PasswordChangerProperty property : IntegrationModuleDAO.
    											getInstance().
								    				getPasswordChangerInstance(module).
								    					getProperties() ) {
    		String displayName = property.getDisplayName();
    		String internalName = property.getInternalName();

     		String value = request.getParameter("mc_"+internalName);
     		if( value == null || value.length() == 0 ) {
     			String valueObject = currentProperties.get(internalName);
     			if( valueObject != null ) {
     				value = valueObject;
     			}
         		if( value == null || value.length() == 0 ) {
         			value = property.getDefaultValue();
             		if( value == null ) {
             			value = "";
             		}
         		}
     		}

     		properties.add(new ScriptProperties(displayName, internalName, value));
    	}

    	return properties;
    }

    /**
     * Bean which holds the displayable name, internal name, and current value of
     * the script properties.
     */

    public class ScriptProperties
    	implements Comparable<ScriptProperties> {
    	private final String displayName;
    	private final String internalName;
    	private final String currentValue;

    	public ScriptProperties( final String newDisplayName,
			final String newInternalName, final String newCurrentValue ) {
    		displayName = newDisplayName;
    		internalName = newInternalName;
    		currentValue = newCurrentValue;
    	}

		public String getCurrentValue() {
			return currentValue;
		}

		public String getDisplayName() {
			return displayName;
		}

		public String getInternalName() {
			return internalName;
		}

		@Override
		public int compareTo(ScriptProperties otherObject) {
			return displayName.compareTo(otherObject.displayName);
		}
    }
}
