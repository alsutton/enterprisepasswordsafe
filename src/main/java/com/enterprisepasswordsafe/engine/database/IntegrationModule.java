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

package com.enterprisepasswordsafe.engine.database;

import java.io.Serializable;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.enterprisepasswordsafe.engine.utils.IDGenerator;

/**
 * Object handling the storage of the details of an integration module.
 */
public final class IntegrationModule
        implements Serializable {
	
    /**
	 * 
	 */
	private static final long serialVersionUID = -8511571861099782080L;

	/**
     * The id of this module.
     */

    private String moduleId;

    /**
     * The name of this module.
     */

    private String name;

    /**
     * The class holding the details of this module.
     */

    private String className;

    /**
     * Creates a new IntegrationModule instance from the data supplied.
     *
     * @param theName
     *            The name of this module.
     * @param theClass
     *            The class for the integrator.
     */

    public IntegrationModule(final String theName, final String theClass) {
        moduleId  = IDGenerator.getID();
        name      = theName;
        className = theClass;
    }

    /**
     * Extracts the information about an integration module from the JDBC ResultSet.
     *
     * @param rs
     *            The result set to extract the data from.
     *
     * @throws SQLException
     *             Thrown if there is a problem extracting the information.
     */

    public IntegrationModule(final ResultSet rs)
        throws SQLException {
        int idx = 1;
        moduleId  = rs.getString(idx++);
        name      = rs.getString(idx++);
        className = rs.getString(idx);
    }
    /**
     * Get the ID of this modules.
     * 
     * @return The ID of the module.
     */
    
    public String getId() {
    	return moduleId;
    }
    
    /**
     * Get the name of this module.
     */
    
    public String getName() {
    	return name;
    }

	public String getClassName() {
		return className;
	}

	public void setClassName(String className) {
		this.className = className;
	}
}
