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

import java.io.UnsupportedEncodingException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.enterprisepasswordsafe.engine.database.derived.IntegrationModuleScriptSummary;
import com.enterprisepasswordsafe.engine.utils.Constants;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;


/**
 * Data access object for passwords.
 */
public final class IntegrationModuleScriptDAO implements ExternalInterface {

    /**
     * The SQL statement to get the script for a given ID.
     */

    private static final String GET_SQL =
            "SELECT   script_id, module_id, name, script"
            + "  FROM intmodules_scripts "
            + " WHERE script_id = ? ";

    /**
     * The SQL statement to get all the available scripts.
     */

    private static final String GET_ALL_SCRIPTS_FOR_MODULE_SQL =
            "SELECT   script_id, module_id, name, script"
            + "  FROM intmodules_scripts "
            + " WHERE module_id = ? ";

    /**
     * The SQL statement to get all the available scripts.
     */

    private static final String GET_ALL_SCRIPTS_FOR_PASSWORD_SQL =
			"SELECT scr.script_id, scr.module_id, scr.name, scr.script "
	    	+   "FROM	intmodules_scripts scr, "
	    	+   "       intmodules_conf conf "
	    	+   "WHERE  conf.parameter_name = '"+IntegrationModuleConfigurationDAO.MODULE_CONFIGURED_PARAMETER+"' "
	    	+   "  AND  conf.script_id = scr.script_id "
	    	+   "  AND  conf.password_id = ?";

    /**
     * Gets all script IDs for a specific module.
     */

    private static final String GET_SCRIPT_IDS_FOR_MODULE_SQL =
            "SELECT   script_id"
            + "  FROM intmodules_scripts "
            + " WHERE module_id = ? ";

    /**
     * Gets all script IDs for a specific module.
     */

    private static final String DELETE_SCRIPTS_FOR_MODULE_SQL =
              "DELETE FROM intmodules_scripts "
            + " WHERE module_id = ? ";

    /**
     * The SQL statement to insert the details of a module into the database.
     */

    private static final String INSERT_SQL_WITH_SCRIPT =
            "INSERT INTO intmodules_scripts(  module_id, name, script, script_id ) "
            + "                     VALUES (         ?,     ?,      ?,         ? ) ";

    /**
     * The SQL statement to insert the details of a module into the database.
     */

    private static final String UPDATE_SQL_WITH_SCRIPT =
              "UPDATE intmodules_scripts "
    	    + "   SET module_id = ?, name = ?, script = ? "
    	    + " WHERE script_id = ?";

    /**
     * SQL to delete the details of a module from the database
     */

    private static final String DELETE_SQL =
           "DELETE FROM intmodules_scripts "
         + "      WHERE script_id = ? ";

    /**
     * The SQL to get the summary details of the password script.
     */

    private static final String GET_SUMMARY_SQL =
    		"SELECT scr.script_id, scr.name, imdl.module_id, imdl.name "
    	+   "FROM	intmodules_scripts scr, "
    	+   "		intmodules imdl "
    	+   "WHERE  scr.module_id = imdl.module_id";

    /**
     * The SQL to get the summary details of scripts active for a give password.
     */

    private static final String GET_SUMMARY_FOR_ACTIVE_SQL =
    		"SELECT scr.script_id, scr.name, imdl.module_id, imdl.name "
    	+   "FROM	intmodules_scripts scr, "
    	+   "       intmodules_conf conf, "
    	+   "		intmodules imdl "
    	+   "WHERE  conf.parameter_name = '"+IntegrationModuleConfigurationDAO.MODULE_CONFIGURED_PARAMETER+"' "
    	+   "  AND  conf.script_id = scr.script_id "
    	+   "  AND  imdl.module_id = scr.module_id "
    	+   "  AND  conf.password_id = ?";

    /**
	 * private constructor to prevent instantiation
	 */

	public IntegrationModuleScriptDAO() {
		super();
	}


    /**
     * Stores the script details in the database.
     *
     * @param conn The connection to the database.
     *
     * @throws SQLException Thrown if there is a problem with the database.
     * @throws UnsupportedEncodingException
     */

    public void update( final IntegrationModuleScript script )
    	throws SQLException, UnsupportedEncodingException {
    	storeWork(UPDATE_SQL_WITH_SCRIPT, script);
    }

    /**
     * Stores the script details in the database.
     *
     * @param conn The connection to the database.
     *
     * @throws SQLException Thrown if there is a problem with the database.
     * @throws UnsupportedEncodingException
     */

    public void store( final IntegrationModuleScript script )
    	throws SQLException, UnsupportedEncodingException {
    	storeWork(INSERT_SQL_WITH_SCRIPT, script);
    }

    /**
     * Stores the script details in the database.
     *
     * @param conn The connection to the database.
     *
     * @throws SQLException Thrown if there is a problem with the database.
     * @throws UnsupportedEncodingException
     */

    public void storeWork( final String sql, final IntegrationModuleScript script )
    	throws SQLException, UnsupportedEncodingException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql);
        try {
        	int idx = 1;
            ps.setString(idx++, script.getModuleId());
            ps.setString(idx++, script.getName());
            String scriptText = script.getScript();
            if( scriptText != null ) {
            	ps.setBytes(idx++, scriptText.getBytes(Constants.STRING_CODING_FORMAT));
            }
            ps.setString(idx, script.getId());
        	ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Delete the script.
     *
     * @param conn The connection to the database.
     */

    public void delete(final IntegrationModuleScript script)
    	throws SQLException {
    	IntegrationModuleConfigurationDAO.getInstance().deleteAllForScript(script.getId());

    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL);
        try {
            ps.setString(1, script.getId());
        	ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets the summary of scripts for a password.
     *
     * @param conn
     *            The connection to the database.
     * @param id
     *            The ID of the password to get the summary for to get.
     *
     * @return The requested script details, or null if it doesn't exist.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     */

    public Set<IntegrationModuleScriptSummary> getScriptSummaries(final String id)
            throws SQLException {
    	Map<String,IntegrationModuleScriptSummary> scriptMap =
    		new HashMap<String,IntegrationModuleScriptSummary>();

    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SUMMARY_SQL);
        try {
            ResultSet rs = ps.executeQuery();
            try {
	            while(rs.next()) {
	            	final String scriptId   = rs.getString(1);
	            	final String name       = rs.getString(2);
	            	final String moduleId   = rs.getString(3);
	            	final String moduleName = rs.getString(4);
	            	scriptMap.put
	            		(
	            			scriptId,
	            			new IntegrationModuleScriptSummary( scriptId, name, moduleId, moduleName, false )
	        			);
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }

    	ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SUMMARY_FOR_ACTIVE_SQL);
        try {
            ps.setString(1, id);
            ResultSet rs = ps.executeQuery();
            try {
	            while(rs.next()) {
	            	int idx = 1;
	            	String scriptId = rs.getString(idx++);
	            	String name = rs.getString(idx++);
	            	String moduleId = rs.getString(idx++);
	            	String moduleName = rs.getString(idx);
	            	scriptMap.put
	            		(
	        				scriptId,
	            			new IntegrationModuleScriptSummary( scriptId, name, moduleId, moduleName, true )
	        			);
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }

    	Set<IntegrationModuleScriptSummary> scripts = new TreeSet<IntegrationModuleScriptSummary>();
    	scripts.addAll(scriptMap.values());
        return scripts;
    }

    /**
     * Gets the scripts for a password.
     *
     * @param conn
     *            The connection to the database.
     * @param id
     *            The ID of the password to get the summary for to get.
     *
     * @return The requested script details, or null if it doesn't exist.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     * @throws UnsupportedEncodingException
     */

    public List<IntegrationModuleScript> getScriptsForPassword(final String itemId)
            throws SQLException, UnsupportedEncodingException {
    	List<IntegrationModuleScript> passwordScripts =
    		new ArrayList<IntegrationModuleScript>();

    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_SCRIPTS_FOR_PASSWORD_SQL);
        try {
            ps.setString(1, itemId);
            ResultSet rs = ps.executeQuery();
            try {
	            while(rs.next()) {
	            	passwordScripts.add( new IntegrationModuleScript(rs) );
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }

        return passwordScripts;
    }

    /**
     * Check to see if a password has scripts configured for it.
     *
     * @param conn
     *            The connection to the database.
     * @param id
     *            The ID of the password to check.
     *
     * @return true if the password has scripts, false if not.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     */

    public boolean hasScripts(final PasswordBase password)
            throws SQLException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_SCRIPTS_FOR_PASSWORD_SQL);
        try {
            ps.setString(1, password.getId());
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
     * Gets a specific script.
     *
     * @param conn
     *            The connection to the database.
     * @param id
     *            The ID of the script to get.
     *
     * @return The requested script details, or null if it doesn't exist.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     * @throws UnsupportedEncodingException
     */

    public IntegrationModuleScript getById(final String id)
            throws SQLException, UnsupportedEncodingException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL);
        try {
            ps.setString(1, id);
            ps.setMaxRows(1);

            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	                return new IntegrationModuleScript(rs);
	            }

	            return null;
	        } finally {
	            DatabaseConnectionUtils.close(rs);
	        }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets a list of script IDs associated with a module.
     *
     * @param conn
     *            The connection to the database.
     * @param id
     *            The ID of the module to get the script IDs for.
     *
     * @return A List of script IDs.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     */

    public List<String> getIDsForModule(final String id) throws SQLException {
    	List<String> scriptIds = new ArrayList<String>();

    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SCRIPT_IDS_FOR_MODULE_SQL);
        try {
            ps.setString(1, id);

            ResultSet rs = ps.executeQuery();
            try {
	            while (rs.next()) {
	                scriptIds.add( rs.getString(1) );
	            }

	            return scriptIds;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets a list of script IDs associated with a module.
     *
     * @param conn
     *            The connection to the database.
     * @param id
     *            The ID of the module to get the script IDs for.
     *
     * @return A List of script IDs.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     */

    public void deleteAllForModule(final String id) throws SQLException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SCRIPTS_FOR_MODULE_SQL);
        try {
            ps.setString(1, id);
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets all of the scripts.
     *
     * @param conn
     *            The connection to the database.
     * @param moduleId
     *            The ID of the module to get the scripts for.
     *
     * @return The scripts configured for the module.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     * @throws UnsupportedEncodingException
     */

    public List<IntegrationModuleScript> getAll( String moduleId)
            throws SQLException, UnsupportedEncodingException {
    	List<IntegrationModuleScript> scripts =
    		new ArrayList<IntegrationModuleScript>();

    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_SCRIPTS_FOR_MODULE_SQL);
        try {
        	ps.setString(1, moduleId);
            ResultSet rs = ps.executeQuery();
            try {
	            while(rs.next()) {
	            	scripts.add( new IntegrationModuleScript(rs) );
	            }

	            return scripts;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    //------------------------

    private static final class InstanceHolder {
    	static final IntegrationModuleScriptDAO INSTANCE = new IntegrationModuleScriptDAO();
    }

    public static IntegrationModuleScriptDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
