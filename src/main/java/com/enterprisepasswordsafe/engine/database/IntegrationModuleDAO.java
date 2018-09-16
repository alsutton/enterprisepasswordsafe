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
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import com.enterprisepasswordsafe.engine.integration.PasswordChanger;
import com.enterprisepasswordsafe.engine.integration.PasswordChangerProperty;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Data access object for passwords.
 */
public final class IntegrationModuleDAO
	implements ExternalInterface {

    /**
     * The SQL statement to get the module for a given ID.
     */

    private static final String GET_SQL =
            "SELECT   module_id, name, className "
            + "  FROM intmodules "
            + " WHERE module_id = ? ";

    /**
     * The SQL statement to insert the details of a module into the database.
     */

    private static final String INSERT_SQL =
            "INSERT INTO intmodules( module_id, name, className ) "
            + "             VALUES (         ?,    ?,         ? ) ";

    /**
     * The SQL statement to get all of the installed modules.
     */

    private static final String GET_ALL_SQL =
              "   SELECT  module_id, name, className "
            + "     FROM intmodules "
            + " ORDER BY name";

    /**
     * SQL to delete the details of a module from the database
     */

    private static final String DELETE_SQL =
           "DELETE FROM intmodules "
         + "      WHERE module_id = ? ";

	/**
     * Check to see if a module has been configured for use with any password.
     */

    private static final String CHECK_FOR_MODULE_USE_SQL =
              "SELECT conf.password_id "
            + "  FROM intmodules_conf conf,"
            + "       intmodules_scripts scripts"
            + " WHERE scripts.module_id = ?"
            + "   AND scripts.script_id = conf.script_id "
            + "   AND conf.parameter_name = '"
            	+IntegrationModuleConfigurationDAO.MODULE_CONFIGURED_PARAMETER
        	+"'";

	/**
	 * Private constructor to prevent instantiation.
	 */

	private IntegrationModuleDAO() {
	}


    /**
     * Install a module.
     *
     * @param module The module to install.
     *
     * @throws Exception Thrown if the module can not be installed.
     */

    public void install(final IntegrationModule module)
            throws Exception {
    	// First run the install method of the integrator class. This
    	// allows the installer to stop the installation if it will
    	// a configuration problem.
    	Class<?> integratorClass = Class.forName(module.getClassName());

    	PasswordChanger changer = (PasswordChanger) integratorClass.newInstance();
    	changer.install(BOMFactory.getDatabaseAbstractionLayer().getConnection());

    	// Delete the details of the node.
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(INSERT_SQL)) {
            int idx = 1;
            ps.setString(idx++, module.getId());
            ps.setString(idx++, module.getName());
            ps.setString(idx,   module.getClassName());
            ps.executeUpdate();
        }
    }

    /**
     * Uninstall a module.
     *
     * @param module The module to uninstall.
     *
     * @throws Exception Thrown if the module can not be uninstalled.
     */

    public void uninstall(final IntegrationModule module)
            throws Exception {
    	// First run the uninstall method of the integrator class. This
    	// allows the uninstaller to stop the removal if uninstallation
    	// will cause a configuration problem.
    	Class<?> integratorClass = Class.forName(module.getClassName());
    	PasswordChanger changer = (PasswordChanger) integratorClass.newInstance();
    	changer.uninstall(BOMFactory.getDatabaseAbstractionLayer().getConnection());

    	// Delete the details of the node.
        try(PreparedStatement deleteStatement = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL)) {
            deleteStatement.setString(1, module.getId());
            deleteStatement.executeUpdate();
        }

        // Delete the configuration
        IntegrationModuleConfigurationDAO.getInstance().deleteAllForModule(module.getId());
    }


    /**
     * Gets a specific module.
     *
     * @param id The ID of the module to get.
     *
     * @return The requested module details, or null if it doesn't exist.
     *
     * @throws SQLException Thrown if there is problem talking to the database.
     */

    public IntegrationModule getById(final String id)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL)) {
            ps.setString(1, id);
            ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new IntegrationModule(rs);
                }
            }
        }

        return null;
    }

    /**
     * Gets all of the configured modules.
     *
     * @return The requested module details, or null if it doesn't exist.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     */

    public List<IntegrationModule> getAll()
            throws SQLException {
    	List<IntegrationModule> modules = new ArrayList<IntegrationModule>();
        try(Statement stmt = BOMFactory.getCurrentConntection().createStatement()) {
            try(ResultSet rs = stmt.executeQuery(GET_ALL_SQL)) {
                while (rs.next()) {
                    modules.add(new IntegrationModule(rs));
                }
            }
        }
        return modules;
    }

    /**
     * Get an instance of the password change associated withe a module.
     *
     * @param module The module to get the password changer for.
     *
     * @return An instance of the password changer.
     */

    public PasswordChanger getPasswordChangerInstance(final IntegrationModule module)
    	throws ClassNotFoundException, InstantiationException, IllegalAccessException {
    	Class<?> integratorClass = Class.forName(module.getClassName());
    	PasswordChanger changer = (PasswordChanger) integratorClass.newInstance();
    	return changer;
    }

    /**
     * Gets the properties for the password changer for a module.
     *
     * @param module The module to get the password changer properties for.
     *
     * @return The List of PasswordChangerProperty's holding the modules property list.
     *
     * @throws ClassNotFoundException Thrown if the module could not be found.
     * @throws IllegalAccessException Thrown if the module class could not be instanciated.
     * @throws InstantiationException Thrown if the module class could not be instanciated.
     */

    public List<PasswordChangerProperty> getPasswordChangerProperties( final IntegrationModule module )
    	throws ClassNotFoundException, InstantiationException, IllegalAccessException {
    	Class<?> integratorClass = Class.forName(module.getClassName());
    	PasswordChanger changer = (PasswordChanger) integratorClass.newInstance();
    	return changer.getProperties();
    }

    /**
     * Check to see if a module is configured for any passwords.
     */

    public boolean isInUse( final IntegrationModule module )
    	throws SQLException {
    	try(PreparedStatement checkPS = BOMFactory.getCurrentConntection().prepareStatement(CHECK_FOR_MODULE_USE_SQL)) {
            checkPS.setString(1, module.getId());
            try(ResultSet rs = checkPS.executeQuery()) {
                return rs.next();
            }
    	}
    }


    private static final class InstanceHolder {
        private static final IntegrationModuleDAO INSTANCE = new IntegrationModuleDAO();
    }

    public static IntegrationModuleDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
