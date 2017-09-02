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

import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.PasswordRestriction;
import com.enterprisepasswordsafe.engine.database.PasswordRestrictionDAO;
import com.enterprisepasswordsafe.engine.dbabstraction.ColumnSpecification;
import com.enterprisepasswordsafe.engine.dbabstraction.IndexSpecification;

public final class PasswordRestrictionsTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "password_restrictions";

	/**
	 * Column information
	 */
	private static final ColumnSpecification ID_COLUMN = new ColumnSpecification("restriction_id", ColumnSpecification.TYPE_ID, true, true);
	private static final ColumnSpecification NAME_COLUMN = new ColumnSpecification("name", ColumnSpecification.TYPE_LONG_STRING);
	private static final ColumnSpecification MIN_NUMERIC_COLUMN = new ColumnSpecification("min_numeric", ColumnSpecification.TYPE_INT);
	private static final ColumnSpecification MIN_LOWER_COLUMN = new ColumnSpecification("min_lower", ColumnSpecification.TYPE_INT);
	private static final ColumnSpecification MIN_UPPER_COLUMN = new ColumnSpecification("min_upper", ColumnSpecification.TYPE_INT);
	private static final ColumnSpecification MIN_SPECIAL_COLUMN = new ColumnSpecification("min_special", ColumnSpecification.TYPE_INT);
    private static final ColumnSpecification MIN_LENGTH_COLUMN = new ColumnSpecification("min_length", ColumnSpecification.TYPE_INT);
    private static final ColumnSpecification MAX_LENGTH_COLUMN = new ColumnSpecification("max_length", ColumnSpecification.TYPE_INT);
    private static final ColumnSpecification SPECIAL_COLUMN = new ColumnSpecification("special", ColumnSpecification.TYPE_SHORT_STRING);
    private static final ColumnSpecification LIFETIME_COLUMN = new ColumnSpecification("lifetime", ColumnSpecification.TYPE_INT);

    private static final ColumnSpecification[] COLUMNS = {
    	ID_COLUMN, NAME_COLUMN, MIN_NUMERIC_COLUMN, MIN_LOWER_COLUMN, MIN_UPPER_COLUMN, MIN_SPECIAL_COLUMN,
    	MIN_LENGTH_COLUMN, MAX_LENGTH_COLUMN, SPECIAL_COLUMN, LIFETIME_COLUMN
    };

    /**
     * Index information
     */

    private static final IndexSpecification ID_INDEX =  new IndexSpecification("pr_ridx", TABLE_NAME, ID_COLUMN);

    private static final IndexSpecification[] INDEXES = {
    	ID_INDEX
    };

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
	 * Creates the table from nothing.
	 */

	@Override
	public void create()
		throws SQLException {
		super.create();
		createDefaultRestrictions();
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
			if( createTableIfNotPresent(ID_COLUMN) ) {
				createDefaultRestrictions();
			}
			createIfNotPresent(LIFETIME_COLUMN);
			createIfNotPresent(MAX_LENGTH_COLUMN);
		}
	}

	/**
	 * Create the default restrictions
	 */

	private void createDefaultRestrictions()
		throws SQLException {
        PasswordRestriction migratedRestriction =
                new PasswordRestriction(
                		"User Login Password Restriction",
                		getCount("lower.min"),
                		getCount("upper.min"),
                		getCount("numeric.min"),
                		getCount("special.min"),
                		getCount("size.min"),
                		getCount("size.min")+32,
                		"\'\"!$%^&*()[]-+=",
                		0);

            PasswordRestrictionDAO prDAO = PasswordRestrictionDAO.getInstance();
            migratedRestriction.setId(PasswordRestriction.LOGIN_PASSWORD_RESTRICTION_ID);
            prDAO.store(migratedRestriction);

            migratedRestriction.setName("Default policy");
            migratedRestriction.setId(PasswordRestriction.MIGRATED_RESTRICTION_ID);
            prDAO.store(migratedRestriction);

            PasswordRestriction restriction = new PasswordRestriction("No Restrictions", 0, 0, 0, 0, 0, 999, "!_", 0);
            prDAO.store(restriction);

            restriction = new PasswordRestriction("Strong Password", 1, 1, 1, 1, 8, 32, "!_?.,", 30);
            prDAO.store(restriction);

            restriction = new PasswordRestriction("Medium Password", 1, 1, 1, 1, 6, 16, "!_?.,", 60);
            prDAO.store(restriction);
	}

    /**
     * Gets the value of an integer property.
     *
     * @param property The name of the property to fetch.
     *
     * @return The value.
     */

    private int getCount(final String property) {
        try {
            String valueString = ConfigurationDAO.getValue(property, null);
            if (valueString != null && !valueString.isEmpty()) {
                return Integer.parseInt(valueString);
            }
        } catch (Exception ex) {
			Logger.getAnonymousLogger().log(Level.SEVERE, "Problem trying to get and parse "+property, ex);
		}
		return 0;
    }


	/**
	 * Gets an instance of this table schema
	 */

	protected static PasswordRestrictionsTable getInstance() {
		return new PasswordRestrictionsTable();
	}
}
