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

package com.enterprisepasswordsafe.engine.database.schema;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;

/**
 * Schema version numbers
 */
public class SchemaVersion {

	/**
	 * The first post EPS 1.58 schema
	 */

	public static final long SCHEMA_201112 = 201112;

    /**
     * The second post EPS 1.58 schema
     */

    public static final long SCHEMA_201212 = 201212;

    /**
	 * The current schema
	 */

	public static final long CURRENT_SCHEMA = SCHEMA_201212;


	private ConfigurationDAO configurationDAO;

	public SchemaVersion() {
		configurationDAO = ConfigurationDAO.getInstance();
	}

	SchemaVersion(ConfigurationDAO configurationDAO) {
		this.configurationDAO = configurationDAO;
	}


	/**
	 * The configuration property which stores the current schema version
	 */

	private static final String CURRENT_SCHEMA_VERSION_PROPERTY = "db.schema.version";

	void create()
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		AuthenticationSourcesTable.getInstance().create();
		ConfigurationTable.getInstance().create();
		EventLogTable.getInstance().create();
		GroupAccessControlTable.getInstance().create();
		GroupAccessRolesTable.getInstance().create();
		GroupsTable.getInstance().create();
		HierarchyAccessControlTable.getInstance().create();
		HierarchyGroupAccessControlTable.getInstance().create();
		HierarchyPasswordDefaultsTable.getInstance().create();
		HierarchyTable.getInstance().create();
		IntegrationModulesConfigurationTable.getInstance().create();
		IntegrationModulesScriptsTable.getInstance().create();
		IntegrationModulesTable.getInstance().create();
		IPZonesTable.getInstance().create();
		LocationsTable.getInstance().create();
		MembershipTable.getInstance().create();
		PasswordHistoryTable.getInstance().create();
		PasswordRestrictionsTable.getInstance().create();
		PasswordsTable.getInstance().create();
		RestrictedAccessApproversTable.getInstance().create();
		RestrictedAccessRequestsTable.getInstance().create();
		UserAccessControl.getInstance().create();
		UserAccessRoles.getInstance().create();
		UserIPZones.getInstance().create();
		UsersTable.getInstance().create();

		GroupDAO gDAO = GroupDAO.getInstance();

		Group epsAdminGroup = new Group(Group.ADMIN_GROUP_ID, "Password Safe Administrators", true);
		gDAO.write(epsAdminGroup);

		gDAO.write(new Group(Group.SUBADMIN_GROUP_ID, "Password Administrators", true));

		Group allGroup = new Group(Group.ALL_USERS_GROUP_ID, "All Users", true);
		gDAO.write(allGroup);

        gDAO.write(new Group(Group.NON_VIEWING_GROUP_ID, "Non-viewing Users", true));

        User adminUser = new User("admin", "admin", "EPS Administrator", "unknown");
		UserDAO.getInstance().write(adminUser, epsAdminGroup, "admin");

		MembershipDAO mDAO = MembershipDAO.getInstance();
		mDAO.create(adminUser, epsAdminGroup);
		mDAO.create(adminUser, allGroup);

		ConfigurationDAO.getInstance().set(ConfigurationOption.SCHEMA_VERSION, Long.toString(CURRENT_SCHEMA));
	}

	public void update()
			throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		synchronized(SchemaVersion.class) {
			Long currentSchema = getCurrentSchemaVersion();
			if (currentSchema == null) {
				create();
				return;
			}
			if (isSchemaCurrent(currentSchema)) {
				return;
			}

			AuthenticationSourcesTable.getInstance().updateSchema(currentSchema);
			ConfigurationTable.getInstance().updateSchema(currentSchema);
			EventLogTable.getInstance().updateSchema(currentSchema);
			GroupsTable.getInstance().updateSchema(currentSchema);
			GroupAccessControlTable.getInstance().updateSchema(currentSchema);
			GroupAccessRolesTable.getInstance().updateSchema(currentSchema);
			HierarchyPasswordDefaultsTable.getInstance().updateSchema(currentSchema);
			HierarchyTable.getInstance().updateSchema(currentSchema);
			LocationsTable.getInstance().updateSchema(currentSchema);
			MembershipTable.getInstance().updateSchema(currentSchema);
			PasswordRestrictionsTable.getInstance().updateSchema(currentSchema);
			PasswordsTable.getInstance().updateSchema(currentSchema);
			RestrictedAccessApproversTable.getInstance().updateSchema(currentSchema);
			RestrictedAccessRequestsTable.getInstance().updateSchema(currentSchema);
			UserAccessControl.getInstance().updateSchema(currentSchema);
			UserAccessRoles.getInstance().updateSchema(currentSchema);
			UserIPZones.getInstance().updateSchema(currentSchema);
			UsersTable.getInstance().updateSchema(currentSchema);

			ConfigurationDAO.getInstance().set(ConfigurationOption.SCHEMA_VERSION, Long.toString(CURRENT_SCHEMA));
		}
	}

	public boolean isSchemaCurrent() {
		Long currentSchema = getCurrentSchemaVersion();
		return isSchemaCurrent(currentSchema);
	}

	private Long getCurrentSchemaVersion() {
		if(!Repositories.databasePoolFactory.isConfigured()) {
			return null;
		}

		return configurationDAO.getLongValue(ConfigurationOption.SCHEMA_VERSION);
	}

	private boolean isSchemaCurrent(final Long currentSchema) {
		return currentSchema != null && currentSchema >= SchemaVersion.CURRENT_SCHEMA;
	}
}
