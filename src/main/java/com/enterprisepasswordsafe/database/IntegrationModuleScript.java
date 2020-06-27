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

package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.utils.Constants;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;

import java.io.UnsupportedEncodingException;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Object handling the storage and manipulation of integration module scripts
 */
public final class IntegrationModuleScript {
    /**
     * The id of the script.
     */

    private final String scriptId;

    /**
     * The ID of the module involved
     */

    private final String moduleId;

    /**
     * The name of the script.
     */
    
    private String name;
    
    /**
     * The script
     */

    private String script;

    /**
     * Creates a new IntegrationModule instance from the data supplied.
     *
     * @param theModuleId
     * 			  The ID of the module.
     * @param theName
     *            The name of this module.
     * @param theScript
     *            The Script to store.
     */

    public IntegrationModuleScript(final String theModuleId, 
    		final String theName, final String theScript) {
    	scriptId 	 = IDGenerator.getID();
        moduleId 	 = theModuleId;
        name     	 = theName;
        script	 	 = theScript;
    }

    /**
     * Extracts the information about an integration module from the JDBC ResultSet.
     *
     * @param rs
     *            The result set to extract the data from.
     *
     * @throws SQLException
     *             Thrown if there is a problem extracting the information.
     * @throws UnsupportedEncodingException 
     */

    public IntegrationModuleScript(final ResultSet rs)
        throws SQLException, UnsupportedEncodingException {
        int idx = 1;
        scriptId	 = rs.getString(idx++);
        moduleId	 = rs.getString(idx++);
        name     	 = rs.getString(idx++);

        byte[] scriptBytes = rs.getBytes(idx);
        script = new String( scriptBytes, Constants.STRING_CODING_FORMAT );
    }

    /**
     * Get the ID of this script.
     * 
     * @return The ID of the script.
     */
    
    public String getId() {
    	return scriptId;
    }
    
    /**
     * Get the ID of the module associated with the script
     * 
     * @return The ID of the module associated with the script.
     */
    
    public String getModuleId() {
    	return moduleId;
    }
    
    /**
     * Get the name of this script.
     * 
     * @return The name of the script.
     */
    
    public String getName() {
    	return name;
    }

    /**
     * Set the name of the script.
     * 
     * @param newName The name of the script.
     */
    
    public void setName(String newName) {
    	name = newName;
    }
    
    /**
     * Get the script.
     * 
     * @return The script.
     * @throws UnsupportedEncodingException 
     */
    
    public String getScript() {
    	return script;
    }
    
    /**
     * Store the script
     * 
     * @param newScript The new Script.
     */
    
    public void setScript(String newScript) {
    	script = newScript;
    }
}
