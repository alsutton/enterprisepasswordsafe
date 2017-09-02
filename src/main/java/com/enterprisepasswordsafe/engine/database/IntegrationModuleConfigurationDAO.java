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

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Object handling the storage of the configuration of an integration module script.
 */
public final class IntegrationModuleConfigurationDAO implements ExternalInterface {

	/**
	 * The maker used to indicate a property setting for a module which is used
	 * for all passwords. NULL is not used due to an issue with HSQLDB 1.8.0.1
	 */

	private static final String ALL_PASSWORDS_MARKER = "*";

	/**
	 * The parameter name used to indicate a module script is configured for a password.
	 */

	public static final String MODULE_CONFIGURED_PARAMETER = "_ACTIVE";

	/**
     * The SQL statement to check if a property exists
     */

    private static final String CHECK_FOR_PARAMETER_SQL =
            "SELECT parameter_value "
            + "  FROM intmodules_conf "
            + " WHERE script_id = ? "
            + "   AND password_id = ? "
            + "   AND parameter_name = ? ";

	/**
     * Check to see if a script has been configured for a password.
     */

    private static final String CHECK_FOR_SCRIPT_USE_SQL =
              "SELECT password_id "
            + "  FROM intmodules_conf"
            + " WHERE script_id = ?"
            + "   AND parameter_name = '"+MODULE_CONFIGURED_PARAMETER+"'";

	/**
     * Deletes all of the properties for a specific module
     */

    private static final String DELETE_ALL_FOR_SCRIPT_SQL =
            "DELETE FROM intmodules_conf "
    	  + " WHERE script_id = ? ";

    /**
     * The SQL statement to get the configuration options for a given module and password.
     */

    private static final String GET_SQL =
            "SELECT   parameter_name, parameter_value"
            + "  FROM intmodules_conf "
            + " WHERE script_id = ? "
            + "   AND password_id = ?";

    /**
     * The SQL statement to insert the details of a module configuration into the database.
     */

    private static final String INSERT_SQL =
            "INSERT INTO intmodules_conf( parameter_name, parameter_value, script_id, password_id ) "
            + "             VALUES      (             ?,              ?,           ?,           ? ) ";

    /**
     * The SQL statement to updatethe details of a module configuration into the database.
     */

    private static final String UPDATE_SQL =
              "UPDATE intmodules_conf "
    	    + "   SET parameter_name = ?, parameter_value = ? "
            + " WHERE script_id = ? "
            + "   AND password_id = ?";

    /**
     * SQL to delete the configuration options relating to a module.
     */

    private static final String DELETE_SQL =
           "DELETE FROM intmodules_conf "
         + "      WHERE script_id = ? "
         + "        AND password_id = ? "
         + "        AND parameter_name = ?";

	/**
	 * Constructor. Stores the connection to the database.
	 */

	private IntegrationModuleConfigurationDAO( ) {
		super();
	}

    /**
     * Store the data.
     *
     * @param conn
     *            The connection to the database.
     *
     * @throws Exception Thrown if there is a problem with the database.
     */

    public void store(final IntegrationModuleScript script,
    		String passwordId, final String propertyName, final String propertyValue)
            throws SQLException {
    	if( passwordId == null ) {
    		passwordId = ALL_PASSWORDS_MARKER;
    	}

    	String sql;
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(CHECK_FOR_PARAMETER_SQL);
    	try {
    		ps.setString(1, script.getId());
    		ps.setString(2, passwordId);
    		ps.setString(3,   propertyName);
    		ps.setMaxRows(1);

            ResultSet rs = ps.executeQuery();
            try {
	        	if( rs.next() ) {
	        		sql = UPDATE_SQL;
	        	} else {
	        		sql = INSERT_SQL;
	        	}
            } finally {
        		DatabaseConnectionUtils.close(rs);
            }
    	} finally {
            DatabaseConnectionUtils.close(ps);
    	}

    	ps = BOMFactory.getCurrentConntection().prepareStatement(sql);
        try {
            ps.setString(1, propertyName);
            ps.setString(2, propertyValue);
            ps.setString(3, script.getId());
           	ps.setString(4, passwordId);
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Check to see if a script is configured for any passwords.
     */

    public boolean scriptIsInUse( final String scriptId )
    	throws SQLException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(CHECK_FOR_SCRIPT_USE_SQL);
    	try {
            ps.setString(1, scriptId);
            ps.setMaxRows(1);
            ResultSet rs = ps.executeQuery();
            try {
            	return rs.next();
        	} finally {
        		DatabaseConnectionUtils.close(rs);
            }
    	} finally {
            DatabaseConnectionUtils.close(ps);
    	}
    }

    /**
     * Delete all of the configuration options for a module.
     */

    public void deleteAllForModule( final String moduleId )
    	throws SQLException {
		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_ALL_FOR_SCRIPT_SQL);
		try {
			for(String scriptId : IntegrationModuleScriptDAO.getInstance().getIDsForModule(moduleId)) {
				ps.setString(1, scriptId);
				ps.addBatch();
			}
			ps.executeBatch();
		} finally {
			DatabaseConnectionUtils.close(ps);
		}

		IntegrationModuleScriptDAO.getInstance().deleteAllForModule(moduleId);
    }

    /**
     * Delete all of the configuration options for a module.
     */

    public void deleteAllForScript( final String scriptId )
    	throws SQLException {
		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_ALL_FOR_SCRIPT_SQL);
		try {
			ps.setString(1, scriptId);
			ps.executeUpdate();
		} finally {
			DatabaseConnectionUtils.close(ps);
		}
    }

    /**
     * Gets the properties for this module.
     *
     * @return The List of PasswordChangerProperty's holding the modules property list.
     *
     * @throws ClassNotFoundException Thrown if the module could not be found.
     * @throws IllegalAccessException Thrown if the module class could not be instanciated.
     * @throws InstantiationException Thrown if the module class could not be instanciated.
     */

    public Map<String,String> getProperties( final IntegrationModuleScript script,
    		final Password password)
    	throws SQLException {
    	// If we're not dealing with the module defaults
    	// we need to obtain them first.
        Map<String,String> properties;
        String passwordId;
        if( password == null ) {
        	properties = new HashMap<String,String>();
        	passwordId = ALL_PASSWORDS_MARKER;
        } else {
        	properties = getProperties( script, null );
        	passwordId = password.getId();
        }


    	final PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL);
        try {
            ps.setString(1, script.getId());
            ps.setString(2,   passwordId);

            final ResultSet rs = ps.executeQuery();
            try {
	            while( rs.next() ) {
	            	final String propertyName = rs.getString(1);
	            	final String propertyValue = rs.getString(2);
	            	properties.put(propertyName, propertyValue);
	            }

	            return properties;
            } finally {
            	DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Delete a property
     *
     * @return The List of PasswordChangerProperty's holding the modules property list.
     *
     * @throws ClassNotFoundException Thrown if the module could not be found.
     * @throws IllegalAccessException Thrown if the module class could not be instanciated.
     * @throws InstantiationException Thrown if the module class could not be instanciated.
     */

    public void deleteProperty( final IntegrationModuleScript script,
    		String passwordId, final String propertyName)
    	throws SQLException {
    	String realPasswordId = passwordId;
    	if( realPasswordId == null ) {
    		realPasswordId = ALL_PASSWORDS_MARKER;
    	}

    	final PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL);
        try {
            ps.setString(1, script.getId());
            ps.setString(2, realPasswordId);
            ps.setString(3, propertyName);
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    //------------------------

    private static class InstanceHolder {
    	static final IntegrationModuleConfigurationDAO INSTANCE = new IntegrationModuleConfigurationDAO();
    }

    public static IntegrationModuleConfigurationDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
