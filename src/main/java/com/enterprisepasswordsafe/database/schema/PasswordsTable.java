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

package com.enterprisepasswordsafe.database.schema;

import com.enterprisepasswordsafe.database.BOMFactory;

import java.lang.reflect.InvocationTargetException;
import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class PasswordsTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	public static final String TABLE_NAME = "passwords";

	/**
	 * The column information
	 */

	private static final ColumnSpecification ID_COLUMN = new ColumnSpecification("password_id", ColumnSpecification.TYPE_ID, false, true);
	private static final ColumnSpecification LOCATION_COLUMN = new ColumnSpecification("location", ColumnSpecification.TYPE_LONG_STRING);
	private static final ColumnSpecification EXPIRY_COLUMN = new ColumnSpecification("expiry", ColumnSpecification.TYPE_LONG_STRING);
	private static final ColumnSpecification ENABLED_COLUMN = new ColumnSpecification("enabled", ColumnSpecification.TYPE_CHAR);
	private static final ColumnSpecification AUDITED_COLUMN = new ColumnSpecification("audited", ColumnSpecification.TYPE_CHAR);
	private static final ColumnSpecification HISTORY_COLUMN = new ColumnSpecification("history_stored", ColumnSpecification.TYPE_CHAR);
	private static final ColumnSpecification RESTRICTION_COLUMN = new ColumnSpecification("restriction_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification RA_ENABLED_COLUMN = new ColumnSpecification("ra_enabled", ColumnSpecification.TYPE_CHAR);
	private static final ColumnSpecification RA_APPROVERS_COLUMN = new ColumnSpecification("ra_approvers", ColumnSpecification.TYPE_INT);
	private static final ColumnSpecification RA_BLOCKERS_COLUMN = new ColumnSpecification("ra_blockers", ColumnSpecification.TYPE_INT);
	private static final ColumnSpecification LOCATION_ID_COLUMN = new ColumnSpecification("location_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification TYPE_COLUMN = new ColumnSpecification("ptype", ColumnSpecification.TYPE_INT);
	private static final ColumnSpecification LAST_CHANGED_COLUMN = new ColumnSpecification("last_changed_l", ColumnSpecification.TYPE_LONG);
	private static final ColumnSpecification DATA_COLUMN = new ColumnSpecification("password_data", ColumnSpecification.TYPE_BLOB);

	private static final ColumnSpecification[] COLUMNS = {
		ID_COLUMN, LOCATION_COLUMN, EXPIRY_COLUMN, ENABLED_COLUMN, TYPE_COLUMN, AUDITED_COLUMN,
		HISTORY_COLUMN, RESTRICTION_COLUMN, RA_ENABLED_COLUMN, RA_APPROVERS_COLUMN,
		RA_BLOCKERS_COLUMN, LAST_CHANGED_COLUMN, LOCATION_ID_COLUMN, DATA_COLUMN
	};

	/**
	 * The index information
	 */

	private static final IndexSpecification ID_INDEX = new IndexSpecification("pw_pidx", TABLE_NAME, ID_COLUMN);

	private static final IndexSpecification[] INDEXES = {
		ID_INDEX
	};

	/**
	 * The SQL to set all the password types to be system.
	 */

	private final String SET_ALL_TO_SYSTEM_SQL = "UPDATE passwords SET ptype = 0";

	/**
	 * The SQL to set all the password types to be system.
	 */

	private final String UPDATE_TO_PERSONAL_PASSWORD_SQL =
		"UPDATE passwords SET ptype = 1 WHERE password_id = ?";

	/**
	 * The SQL to set all the password types to be system.
	 */

	private final String SELECT_PERSONAL_PASSWORDS_SQL =
		"SELECT name FROM hierarchy WHERE parent_id = ? ";

	/**
	 * Get the list of personal password nodes
	 */

	private final String GET_PERONAL_NODE_IDS =
		"SELECT node_id FROM hierarchy WHERE type = 2";

	/**
	 * Get the name of this table
	 */

	@Override
	public String getTableName() {
		return TABLE_NAME;
	}

	/**
	 * Get all of the columns in the table
	 */

	@Override
	ColumnSpecification[] getAllColumns() {
		return COLUMNS;
	}

	/**
	 * Get all of the indexes in the table
	 */

	@Override
	IndexSpecification[] getAllIndexes() {
		return INDEXES;
	}

	/**
	 * Update the current schema to the latest version
	 */

	@Override
	public void updateSchema(final long schemaID)
		throws SQLException {
		if(schemaID >= SchemaVersion.CURRENT_SCHEMA)
			return;

		if(schemaID < SchemaVersion.SCHEMA_201112) {
			createIfNotPresent(RA_ENABLED_COLUMN);
			createIfNotPresent(RA_BLOCKERS_COLUMN);
			createIfNotPresent(RA_APPROVERS_COLUMN);
			createIfNotPresent(RESTRICTION_COLUMN);
			createIfNotPresent(LAST_CHANGED_COLUMN);
			createIfNotPresent(EXPIRY_COLUMN);
			createIfNotPresent(AUDITED_COLUMN);
			createIfNotPresent(DATA_COLUMN);
			createIfNotPresent(TYPE_COLUMN);
			try {
				createTypes();
			} catch(Exception ex) {
				Logger.getAnonymousLogger().log(Level.SEVERE, "Database password types not migrated successfully", ex);
			}
		}
	}

	   /**
     * Code to migrate existing locations to be hierarchy positions.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws IllegalAccessException
     * @throws InstantiationException
     */

    private void createTypes()
			throws SQLException, InstantiationException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {
		Connection conn = BOMFactory.getDatabaseAbstractionLayer().getConnection();

    	try(Statement stmt = conn.createStatement()) {
			stmt.executeUpdate(SET_ALL_TO_SYSTEM_SQL);

			try (PreparedStatement updatePS = conn.prepareStatement(UPDATE_TO_PERSONAL_PASSWORD_SQL)) {
				try (PreparedStatement selectPS = conn.prepareStatement(SELECT_PERSONAL_PASSWORDS_SQL)) {
					try (ResultSet rs = stmt.executeQuery(GET_PERONAL_NODE_IDS)) {
						while (rs.next()) {
							String id = rs.getString(1);
							selectPS.setString(1, id);

							try (ResultSet selectRS = selectPS.executeQuery()) {
								while (selectRS.next()) {
									String passwordID = selectRS.getString(1);
									updatePS.setString(1, passwordID);
									updatePS.executeUpdate();
								}
							}
						}
					}
				}
			}
        }
    }

	/**
	 * Gets an instance of this table schema
	 */

	static PasswordsTable getInstance() {
		return new PasswordsTable();
	}
}
