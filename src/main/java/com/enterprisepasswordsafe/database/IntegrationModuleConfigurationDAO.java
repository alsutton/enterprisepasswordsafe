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

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public final class IntegrationModuleConfigurationDAO
		extends JDBCBase {

	private static final String ALL_PASSWORDS_MARKER = "*";

	public static final String MODULE_CONFIGURED_PARAMETER = "_ACTIVE";

    private static final String CHECK_FOR_PARAMETER_SQL =
            "SELECT parameter_value FROM intmodules_conf "
            + " WHERE script_id = ? AND password_id = ? AND parameter_name = ? ";

    private static final String CHECK_FOR_SCRIPT_USE_SQL =
              "SELECT password_id FROM intmodules_conf"
            + " WHERE script_id = ? AND parameter_name = '"+MODULE_CONFIGURED_PARAMETER+"'";

    private static final String DELETE_ALL_FOR_SCRIPT_SQL =
            "DELETE FROM intmodules_conf WHERE script_id = ? ";

    private static final String GET_SQL =
            "SELECT parameter_name, parameter_value FROM intmodules_conf WHERE script_id = ? AND password_id = ?";

    private static final String INSERT_SQL =
            "INSERT INTO intmodules_conf( parameter_name, parameter_value, script_id, password_id ) "
            + "             VALUES      (             ?,              ?,           ?,           ? ) ";

    private static final String UPDATE_SQL =
              "UPDATE intmodules_conf SET parameter_name = ?, parameter_value = ? "
            + " WHERE script_id = ? AND password_id = ?";

    private static final String DELETE_SQL =
           "DELETE FROM intmodules_conf WHERE script_id = ? AND password_id = ? AND parameter_name = ?";

	private IntegrationModuleConfigurationDAO( ) {
		super();
	}

    public void store(final IntegrationModuleScript script,
    		String passwordId, final String propertyName, final String propertyValue)
            throws SQLException {
    	if( passwordId == null ) {
    		passwordId = ALL_PASSWORDS_MARKER;
    	}

    	String sql = determineStoreSQL(script, passwordId, propertyName);
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            ps.setString(1, propertyName);
            ps.setString(2, propertyValue);
            ps.setString(3, script.getId());
           	ps.setString(4, passwordId);
            ps.executeUpdate();
        }
    }

    private String determineStoreSQL(IntegrationModuleScript script, String passwordId, final String propertyName)
			throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(CHECK_FOR_PARAMETER_SQL)) {
			ps.setString(1, script.getId());
			ps.setString(2, passwordId);
			ps.setString(3,   propertyName);
			ps.setMaxRows(1);
			try(ResultSet rs = ps.executeQuery()) {
				return rs.next() ? UPDATE_SQL : INSERT_SQL;
			}
		}
	}

    public boolean scriptIsInUse( final String scriptId )
    	throws SQLException {
		return exists(CHECK_FOR_SCRIPT_USE_SQL, scriptId);
    }

    public void deleteAllForModule( final String moduleId )
    	throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_ALL_FOR_SCRIPT_SQL)) {
			for(String scriptId : IntegrationModuleScriptDAO.getInstance().getIDsForModule(moduleId)) {
				ps.setString(1, scriptId);
				ps.addBatch();
			}
			ps.executeBatch();
		}

		IntegrationModuleScriptDAO.getInstance().deleteAllForModule(moduleId);
    }

    public void deleteAllForScript( final String scriptId )
    	throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_ALL_FOR_SCRIPT_SQL)) {
			ps.setString(1, scriptId);
			ps.executeUpdate();
		}
    }

    public Map<String,String> getProperties(final IntegrationModuleScript script, final Password password)
    	throws SQLException {
    	// If we're not dealing with the module defaults
    	// we need to obtain them first.
        Map<String,String> properties;
        String passwordId;
        if( password == null ) {
        	properties = new HashMap<>();
        	passwordId = ALL_PASSWORDS_MARKER;
        } else {
        	properties = getProperties( script, null );
        	passwordId = password.getId();
        }
        addPasswordSpecificProperties(script, password, properties);
        return properties;
    }

    private void addPasswordSpecificProperties(final IntegrationModuleScript script, final Password password,
											   final Map<String,String> properties)
			throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL)) {
			ps.setString(1, script.getId());
			ps.setString(2,   password.getId());
			try(ResultSet rs = ps.executeQuery()) {
				while( rs.next() ) {
					final String propertyName = rs.getString(1);
					final String propertyValue = rs.getString(2);
					properties.put(propertyName, propertyValue);
				}
			}
		}
	}

    public void deleteProperty( final IntegrationModuleScript script, String passwordId, final String propertyName)
    	throws SQLException {
    	String realPasswordId = passwordId;
    	if( realPasswordId == null ) {
    		realPasswordId = ALL_PASSWORDS_MARKER;
    	}

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL)) {
            ps.setString(1, script.getId());
            ps.setString(2, realPasswordId);
            ps.setString(3, propertyName);
            ps.executeUpdate();
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
