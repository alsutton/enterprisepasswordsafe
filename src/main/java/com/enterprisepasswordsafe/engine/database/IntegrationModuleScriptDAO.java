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

import com.enterprisepasswordsafe.engine.database.derived.IntegrationModuleScriptSummary;
import com.enterprisepasswordsafe.engine.utils.Constants;

import java.io.UnsupportedEncodingException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

public final class IntegrationModuleScriptDAO {

    private static final String GET_SQL =
            "SELECT   script_id, module_id, name, script FROM intmodules_scripts WHERE script_id = ? ";

    private static final String GET_ALL_SCRIPTS_FOR_MODULE_SQL =
            "SELECT   script_id, module_id, name, script FROM intmodules_scripts WHERE module_id = ? ";

    private static final String GET_ALL_SCRIPTS_FOR_PASSWORD_SQL =
			"SELECT scr.script_id, scr.module_id, scr.name, scr.script "
	    	+   "FROM	intmodules_scripts scr, intmodules_conf conf "
	    	+   "WHERE  conf.parameter_name = '"+IntegrationModuleConfigurationDAO.MODULE_CONFIGURED_PARAMETER+"' "
	    	+   "  AND  conf.script_id = scr.script_id AND conf.password_id = ?";

    private static final String GET_SCRIPT_IDS_FOR_MODULE_SQL =
            "SELECT   script_id FROM intmodules_scripts WHERE module_id = ? ";

    private static final String DELETE_SCRIPTS_FOR_MODULE_SQL =
              "DELETE FROM intmodules_scripts WHERE module_id = ? ";

    private static final String INSERT_SQL_WITH_SCRIPT =
            "INSERT INTO intmodules_scripts(  module_id, name, script, script_id ) VALUES ( ?, ?, ?, ? ) ";

    private static final String UPDATE_SQL_WITH_SCRIPT =
              "UPDATE intmodules_scripts SET module_id = ?, name = ?, script = ? WHERE script_id = ?";

    private static final String DELETE_SQL =
           "DELETE FROM intmodules_scripts WHERE script_id = ? ";

    private static final String GET_SUMMARY_SQL =
    		"SELECT scr.script_id, scr.name, imdl.module_id, imdl.name "
    	+   "FROM intmodules_scripts scr, intmodules imdl WHERE scr.module_id = imdl.module_id";

    private static final String GET_SUMMARY_FOR_ACTIVE_SQL =
    		"SELECT scr.script_id, scr.name, imdl.module_id, imdl.name "
    	+   "FROM	intmodules_scripts scr, intmodules_conf conf, intmodules imdl "
    	+   "WHERE  conf.parameter_name = '"+IntegrationModuleConfigurationDAO.MODULE_CONFIGURED_PARAMETER+"' "
    	+   "  AND  conf.script_id = scr.script_id AND  imdl.module_id = scr.module_id AND  conf.password_id = ?";

	public IntegrationModuleScriptDAO() {
		super();
	}

    public void update( final IntegrationModuleScript script )
    	throws SQLException, UnsupportedEncodingException {
    	storeWork(UPDATE_SQL_WITH_SCRIPT, script);
    }

    public void store( final IntegrationModuleScript script )
    	throws SQLException, UnsupportedEncodingException {
    	storeWork(INSERT_SQL_WITH_SCRIPT, script);
    }

    public void storeWork( final String sql, final IntegrationModuleScript script )
    	throws SQLException, UnsupportedEncodingException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
        	int idx = 1;
            ps.setString(idx++, script.getModuleId());
            ps.setString(idx++, script.getName());
            String scriptText = script.getScript();
            if( scriptText != null ) {
            	ps.setBytes(idx++, scriptText.getBytes(Constants.STRING_CODING_FORMAT));
            }
            ps.setString(idx, script.getId());
        	ps.executeUpdate();
        }
    }

    public void delete(final IntegrationModuleScript script)
    	throws SQLException {
    	IntegrationModuleConfigurationDAO.getInstance().deleteAllForScript(script.getId());
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL)) {
            ps.setString(1, script.getId());
        	ps.executeUpdate();
        }
    }

    public Set<IntegrationModuleScriptSummary> getScriptSummaries(final String id)
            throws SQLException {
    	Map<String,IntegrationModuleScriptSummary> scriptMap = getScriptMapSummaries();

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SUMMARY_FOR_ACTIVE_SQL)) {
            ps.setString(1, id);
            try(ResultSet rs = ps.executeQuery()) {
	            while(rs.next()) {
	            	int idx = 1;
	            	String scriptId = rs.getString(idx++);
	            	String name = rs.getString(idx++);
	            	String moduleId = rs.getString(idx++);
	            	String moduleName = rs.getString(idx);
	            	scriptMap.put(scriptId,
                        new IntegrationModuleScriptSummary( scriptId, name, moduleId, moduleName, true ));
	            }
            }
        }

        return new TreeSet<>(scriptMap.values());
    }

    private Map<String,IntegrationModuleScriptSummary> getScriptMapSummaries()
            throws SQLException {
        Map<String,IntegrationModuleScriptSummary> scriptMap = new HashMap<>();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SUMMARY_SQL)) {
            try(ResultSet rs = ps.executeQuery()) {
                while(rs.next()) {
                    final String scriptId   = rs.getString(1);
                    final String name       = rs.getString(2);
                    final String moduleId   = rs.getString(3);
                    final String moduleName = rs.getString(4);
                    scriptMap.put(scriptId,
                            new IntegrationModuleScriptSummary( scriptId, name, moduleId, moduleName, false ));
                }
            }
        }
        return scriptMap;
    }

    public List<IntegrationModuleScript> getScriptsForPassword(final String itemId)
            throws SQLException, UnsupportedEncodingException {
    	List<IntegrationModuleScript> passwordScripts = new ArrayList<>();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_SCRIPTS_FOR_PASSWORD_SQL)) {
            ps.setString(1, itemId);
            try(ResultSet rs = ps.executeQuery()) {
	            while(rs.next()) {
	            	passwordScripts.add( new IntegrationModuleScript(rs) );
	            }
            }
        }
        return passwordScripts;
    }

    public boolean hasScripts(final PasswordBase password)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_SCRIPTS_FOR_PASSWORD_SQL)) {
            ps.setString(1, password.getId());
            ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
	            return rs.next();
	        }
        }
    }

    public IntegrationModuleScript getById(final String id)
            throws SQLException, UnsupportedEncodingException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL)) {
            ps.setString(1, id);
            ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
	            return rs.next() ? new IntegrationModuleScript(rs) : null;
	        }
        }
    }

    public List<String> getIDsForModule(final String id) throws SQLException {
    	List<String> scriptIds = new ArrayList<>();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SCRIPT_IDS_FOR_MODULE_SQL)) {
            ps.setString(1, id);
            try(ResultSet rs = ps.executeQuery()) {
	            while (rs.next()) {
	                scriptIds.add( rs.getString(1) );
	            }

	            return scriptIds;
            }
        }
    }

    public void deleteAllForModule(final String id) throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SCRIPTS_FOR_MODULE_SQL)) {
            ps.setString(1, id);
            ps.executeUpdate();
        }
    }

    public List<IntegrationModuleScript> getAll(final String moduleId)
            throws SQLException, UnsupportedEncodingException {
    	List<IntegrationModuleScript> scripts = new ArrayList<>();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_SCRIPTS_FOR_MODULE_SQL)) {
        	ps.setString(1, moduleId);
            try(ResultSet rs = ps.executeQuery()) {
	            while(rs.next()) {
	            	scripts.add( new IntegrationModuleScript(rs) );
	            }

	            return scripts;
            }
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
