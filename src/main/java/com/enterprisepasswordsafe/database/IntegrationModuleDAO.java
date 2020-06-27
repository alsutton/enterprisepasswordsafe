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

import com.enterprisepasswordsafe.engine.integration.PasswordChanger;
import com.enterprisepasswordsafe.engine.integration.PasswordChangerProperty;

import java.lang.reflect.InvocationTargetException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

public final class IntegrationModuleDAO
        extends StoredObjectFetcher<IntegrationModule> {

    private static final String GET_SQL = "SELECT module_id, name, className FROM intmodules WHERE module_id = ? ";

    private static final String INSERT_SQL = "INSERT INTO intmodules( module_id, name, className ) VALUES ( ?, ?, ? ) ";

    private static final String GET_ALL_SQL = "SELECT  module_id, name, className FROM intmodules ORDER BY name";

    private static final String DELETE_SQL = "DELETE FROM intmodules WHERE module_id = ? ";

    private static final String CHECK_FOR_MODULE_USE_SQL =
              "SELECT conf.password_id FROM intmodules_conf conf, intmodules_scripts scripts"
            + " WHERE scripts.module_id = ? AND scripts.script_id = conf.script_id "
            + "   AND conf.parameter_name = '" + IntegrationModuleConfigurationDAO.MODULE_CONFIGURED_PARAMETER  + "'";

	private IntegrationModuleDAO() {
	}

    @Override
    IntegrationModule newInstance(ResultSet rs) throws SQLException {
        return new IntegrationModule(rs);
    }

    public void install(final IntegrationModule module)
            throws Exception {
    	// First run the install method of the integrator class. This
    	// allows the installer to stop the installation if it will
    	// a configuration problem.
    	Class<?> integratorClass = Class.forName(module.getClassName());

    	PasswordChanger changer = (PasswordChanger) integratorClass.getDeclaredConstructor().newInstance();
    	changer.install(BOMFactory.getDatabaseAbstractionLayer().getConnection());

    	// Delete the details of the node.
        runResultlessParameterisedSQL(INSERT_SQL, module.getId(), module.getName(), module.getClassName());
    }

    public void uninstall(final IntegrationModule module)
            throws Exception {
    	// First run the uninstall method of the integrator class. This
    	// allows the uninstaller to stop the removal if uninstallation
    	// will cause a configuration problem.
    	Class<?> integratorClass = Class.forName(module.getClassName());
    	PasswordChanger changer = (PasswordChanger) integratorClass.getDeclaredConstructor().newInstance();
    	changer.uninstall(BOMFactory.getDatabaseAbstractionLayer().getConnection());

    	// Delete the details of the node.
        runResultlessParameterisedSQL(DELETE_SQL, module.getId());

        // Delete the configuration
        IntegrationModuleConfigurationDAO.getInstance().deleteAllForModule(module.getId());
    }

    public IntegrationModule getById(final String id)
            throws SQLException {
	    return fetchObjectIfExists(GET_SQL, id);
    }

    public List<IntegrationModule> getAll()
            throws SQLException {
	    return getMultiple(GET_ALL_SQL);
    }

    public PasswordChanger getPasswordChangerInstance(final IntegrationModule module)
            throws ClassNotFoundException, InstantiationException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {
    	Class<?> integratorClass = Class.forName(module.getClassName());
        return (PasswordChanger) integratorClass.getDeclaredConstructor().newInstance();
    }

    public List<PasswordChangerProperty> getPasswordChangerProperties( final IntegrationModule module )
            throws ClassNotFoundException, InstantiationException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {
    	Class<?> integratorClass = Class.forName(module.getClassName());
    	PasswordChanger changer = (PasswordChanger) integratorClass.getDeclaredConstructor().newInstance();
    	return changer.getProperties();
    }

    public boolean isInUse( final IntegrationModule module )
    	throws SQLException {
	    return exists(CHECK_FOR_MODULE_USE_SQL, module.getId());
    }

    private static final class InstanceHolder {
        private static final IntegrationModuleDAO INSTANCE = new IntegrationModuleDAO();
    }

    public static IntegrationModuleDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
